#!/usr/bin/env python3
"""
Async (background) delegation registry.

Backs ``delegate_task(background=true)``: the parent agent dispatches a
subagent that runs on a module-level daemon executor and returns a handle
immediately, so the user and the model can keep working while the child runs.

When the child finishes, a completion event is pushed onto the SHARED
``process_registry.completion_queue`` with ``type="async_delegation"``. The
CLI (``cli.py`` process_loop) and gateway (``_run_process_watcher`` /
``completion_queue`` drain) already poll that queue while the agent is idle
and forge a fresh user/internal turn from each event. We deliberately reuse
that rail rather than reaching into a running agent loop:

  - completions surface as a NEW turn when the agent is idle, never spliced
    between a tool result and an assistant message. That keeps strict
    message-role alternation legal and the prompt cache intact (hard
    invariant: never mutate past context).
  - we inherit the queue's de-dup, crash-recovery checkpoint, and the
    existing CLI + gateway drain wiring for free — no new drain loops in the
    two largest files in the repo.

The completion payload carries a RICH, self-contained task-source block (the
original goal, the context the parent supplied, toolsets, model, dispatch
time, status, and the full result summary). When the result re-enters the
conversation the parent may be deep in unrelated context and won't remember
why the subagent existed; the block lets it either use the result or
re-dispatch if the world has moved on.

This module owns ONLY the async lifecycle. The actual child build + run is
delegated back to ``delegate_tool._run_single_child`` via an injected
runner, so all the credential leasing, heartbeat, timeout, and result-shaping
logic stays in one place.
"""

from __future__ import annotations

import inspect
import logging
import threading
import time
import uuid
import weakref
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _worker
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class _DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """ThreadPoolExecutor variant whose workers do not block process exit.

    Stdlib ``ThreadPoolExecutor`` workers are non-daemon. Background
    delegation is explicitly best-effort detached work, so a long child should
    be interruptible by ``/stop``/shutdown but must not keep a CLI process alive
    after the user exits.
    """

    def _adjust_thread_count(self) -> None:
        if self._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            worker_params = inspect.signature(_worker).parameters
            if len(worker_params) == 3 and hasattr(self, "_create_worker_context"):
                args = (
                    weakref.ref(self, weakref_cb),
                    self._create_worker_context(),
                    self._work_queue,
                )
            else:
                initializer = getattr(self, "_initializer", None)
                initargs = getattr(self, "_initargs", ())
                args = (
                    weakref.ref(self, weakref_cb),
                    self._work_queue,
                    initializer,
                    initargs,
                )
            t = threading.Thread(
                name=thread_name,
                target=_worker,
                args=args,
                daemon=True,
            )
            t.start()
            self._threads.add(t)


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
# A persistent daemon executor (NOT a `with ThreadPoolExecutor()` block, which
# would join on exit and defeat the whole point of async). Workers are daemon
# threads so a hard process exit doesn't hang on an in-flight child.
_executor: Optional[ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_executor_max_workers: int = 0

_records_lock = threading.Lock()
# delegation_id -> record dict. Kept for the lifetime of the run plus a short
# tail after completion so `list_async_delegations()` can show recent results.
_records: Dict[str, Dict[str, Any]] = {}

_DEFAULT_MAX_ASYNC_CHILDREN = 3
# How many completed records to retain for status queries before pruning.
_MAX_RETAINED_COMPLETED = 50


def _get_executor(max_workers: int) -> ThreadPoolExecutor:
    """Lazily create (or grow) the shared daemon executor.

    We never shrink — ThreadPoolExecutor can't resize — but if the configured
    cap grows between calls we rebuild a larger pool. Existing in-flight
    futures keep running on the old pool until it's garbage collected.
    """
    global _executor, _executor_max_workers
    with _executor_lock:
        if _executor is None or max_workers > _executor_max_workers:
            # Daemon threads: thread_name_prefix aids debugging in stack dumps.
            _executor = _DaemonThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="async-delegate",
            )
            _executor_max_workers = max_workers
        return _executor


def active_count() -> int:
    """Number of async delegations currently running."""
    with _records_lock:
        return sum(1 for r in _records.values() if r.get("status") == "running")


def _new_delegation_id() -> str:
    return f"deleg_{uuid.uuid4().hex[:8]}"


def _prune_completed_locked() -> None:
    """Drop the oldest completed records beyond the retention cap.

    Caller must hold ``_records_lock``.
    """
    completed = [
        (rid, r)
        for rid, r in _records.items()
        if r.get("status") != "running"
    ]
    if len(completed) <= _MAX_RETAINED_COMPLETED:
        return
    # Oldest-first by completion time (fall back to dispatch time).
    completed.sort(key=lambda kv: kv[1].get("completed_at") or kv[1].get("dispatched_at") or 0)
    for rid, _ in completed[: len(completed) - _MAX_RETAINED_COMPLETED]:
        _records.pop(rid, None)


def dispatch_async_delegation(
    *,
    goal: str,
    context: Optional[str],
    toolsets: Optional[List[str]],
    role: str,
    model: Optional[str],
    session_key: str,
    runner: Callable[[], Dict[str, Any]],
    interrupt_fn: Optional[Callable[[], None]] = None,
    completion_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_async_children: int = _DEFAULT_MAX_ASYNC_CHILDREN,
    observability_context: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Spawn ``runner`` on the daemon executor and return a handle immediately.

    Parameters
    ----------
    goal, context, toolsets, role, model
        The dispatch-time task spec, captured verbatim for the rich
        completion block.
    session_key
        The gateway session_key (from ``tools.approval.get_current_session_key``)
        captured on the parent thread BEFORE dispatch, because the daemon
        worker thread won't carry the contextvar. Used to route the
        completion back to the originating session.
    runner
        Zero-arg callable that builds + runs the child and returns the same
        result dict ``_run_single_child`` produces. Runs on the worker thread.
    interrupt_fn
        Optional callable to signal the child to stop (used on shutdown /
        explicit cancel).
    completion_callback
        Optional internal callback invoked with the finalized record before
        retention pruning. Used by owners that need authoritative lifecycle
        state without polling the bounded recent-record list.
    max_async_children
        Concurrency cap. When at capacity the dispatch is REJECTED (the caller
        should fall back to sync or tell the user) rather than queued, so a
        runaway model can't pile up unbounded background work.

    Returns
    -------
    dict
        ``{"status": "dispatched", "delegation_id": ...}`` on success, or
        ``{"status": "rejected", "error": ...}`` when at capacity.
    """
    delegation_id = _new_delegation_id()
    dispatched_at = time.time()
    if observability_context is not None:
        observability_context.setdefault("delegation_id", delegation_id)
    record: Dict[str, Any] = {
        "delegation_id": delegation_id,
        "goal": goal,
        "context": context,
        "toolsets": list(toolsets) if toolsets else None,
        "role": role,
        "model": model,
        "session_key": session_key,
        "status": "running",
        "dispatched_at": dispatched_at,
        "completed_at": None,
        "interrupt_fn": interrupt_fn,
        "completion_callback": completion_callback,
    }
    if observability_context:
        record["observability_context"] = dict(observability_context)
    # Capacity check and record insert under ONE lock hold — checking
    # active_count() separately would let two concurrent dispatches (e.g.
    # from different gateway sessions) both pass the check and exceed the cap.
    with _records_lock:
        running = sum(
            1 for r in _records.values() if r.get("status") == "running"
        )
        if running >= max_async_children:
            return {
                "status": "rejected",
                "error": (
                    f"Async delegation capacity reached ({max_async_children} "
                    f"running). Wait for one to finish (its result will re-enter "
                    f"the chat), or run this task synchronously "
                    f"(background=false). Raise delegation.max_async_children in "
                    f"config.yaml to allow more concurrent background subagents."
                ),
            }
        _records[delegation_id] = record

    executor = _get_executor(max_async_children)

    def _worker() -> None:
        result: Dict[str, Any] = {}
        status = "error"
        try:
            result = runner() or {}
            status = result.get("status") or "completed"
        except Exception as exc:  # noqa: BLE001 — must never crash the worker
            logger.exception("Async delegation %s crashed", delegation_id)
            result = {
                "status": "error",
                "summary": None,
                "error": f"{type(exc).__name__}: {exc}",
                "api_calls": 0,
                "duration_seconds": round(time.time() - dispatched_at, 2),
            }
            status = "error"
        finally:
            _finalize(delegation_id, result, status)

    try:
        executor.submit(_worker)
    except Exception as exc:  # pragma: no cover — pool submit failure is rare
        with _records_lock:
            _records.pop(delegation_id, None)
        return {
            "status": "rejected",
            "error": f"Failed to schedule async delegation: {exc}",
        }

    logger.info(
        "Dispatched async delegation %s (session_key=%s): %s",
        delegation_id, session_key or "<cli>", (goal or "")[:80],
    )
    return {"status": "dispatched", "delegation_id": delegation_id}


def _finalize(delegation_id: str, result: Dict[str, Any], status: str) -> None:
    """Mark a record complete and push the completion event onto the queue."""
    with _records_lock:
        record = _records.get(delegation_id)
        if record is None:
            return
        record["status"] = status
        record["completed_at"] = time.time()
        record["summary"] = result.get("summary")
        record["error"] = result.get("error")
        record["api_calls"] = result.get("api_calls", 0)
        record["duration_seconds"] = result.get(
            "duration_seconds",
            round(
                record["completed_at"]
                - (record.get("dispatched_at") or record["completed_at"]),
                2,
            ),
        )
        for key in (
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "cost_usd",
            "exit_reason",
            "model",
        ):
            if key in result and result.get(key) is not None:
                record[key] = result.get(key)
        record["interrupt_fn"] = None  # drop the closure; child is done
        completion_callback = record.get("completion_callback")
        record["completion_callback"] = None
        # Snapshot fields needed for the event while holding the lock.
        event_record = dict(record)
        _prune_completed_locked()

    if callable(completion_callback):
        try:
            completion_callback(event_record)
        except Exception:
            logger.exception("Async delegation %s completion callback failed", delegation_id)
    _push_completion_event(event_record, result, status)


def _push_completion_event(
    record: Dict[str, Any], result: Dict[str, Any], status: str
) -> None:
    """Push a type='async_delegation' event onto the shared completion queue.

    Best-effort: a failure here must not crash the worker, but it WOULD mean a
    silently-lost result, so we log loudly.
    """
    try:
        from tools.process_registry import process_registry
    except Exception as exc:  # pragma: no cover
        logger.error(
            "Async delegation %s finished but process_registry import failed; "
            "result lost: %s",
            record.get("delegation_id"), exc,
        )
        return

    summary = result.get("summary")
    error = result.get("error")
    dispatched_at = record.get("dispatched_at") or time.time()
    completed_at = record.get("completed_at") or time.time()

    evt = {
        "type": "async_delegation",
        "delegation_id": record.get("delegation_id"),
        # session_key routes the completion back to the originating gateway
        # session; empty string => CLI (single-session) path.
        "session_key": record.get("session_key", ""),
        "goal": record.get("goal", ""),
        "context": record.get("context"),
        "toolsets": record.get("toolsets"),
        "role": record.get("role"),
        "model": result.get("model") or record.get("model"),
        "status": status,
        "summary": summary,
        "error": error,
        "api_calls": result.get("api_calls", 0),
        "duration_seconds": result.get(
            "duration_seconds", round(completed_at - dispatched_at, 2)
        ),
        "dispatched_at": dispatched_at,
        "completed_at": completed_at,
        "exit_reason": result.get("exit_reason"),
    }
    observability_context = record.get("observability_context")
    if isinstance(observability_context, dict):
        evt.update(observability_context)
    try:
        process_registry.completion_queue.put(evt)
    except Exception as exc:  # pragma: no cover
        logger.error(
            "Async delegation %s: failed to enqueue completion event; "
            "result lost: %s",
            record.get("delegation_id"), exc,
        )


def list_async_delegations() -> List[Dict[str, Any]]:
    """Snapshot of async delegations (running + recently completed).

    Safe to call from any thread. Excludes the non-serialisable interrupt_fn.
    """
    with _records_lock:
        return [
            {
                k: v
                for k, v in r.items()
                if k not in {"interrupt_fn", "completion_callback"}
            }
            for r in _records.values()
        ]


def interrupt_all(reason: str = "shutdown") -> int:
    """Signal every running async delegation to stop. Returns how many.

    Used on ``/stop`` and gateway shutdown so a dangling background subagent
    can't keep burning tokens with no one listening. The child still emits a
    completion event (status='interrupted') via the normal finalize path.
    """
    count = 0
    with _records_lock:
        targets = [
            r for r in _records.values() if r.get("status") == "running"
        ]
    for r in targets:
        fn = r.get("interrupt_fn")
        if callable(fn):
            try:
                fn()
                count += 1
            except Exception as exc:
                logger.debug(
                    "interrupt_all: %s interrupt failed: %s",
                    r.get("delegation_id"), exc,
                )
    if count:
        logger.info("Interrupted %d async delegation(s) (%s)", count, reason)
    return count


def interrupt_delegation(delegation_id: str, reason: str = "cancelled") -> bool:
    """Signal one running async delegation to stop.

    Returns True when an interrupt function was found and called. The worker
    still owns final status and completion-event delivery.
    """
    with _records_lock:
        record = _records.get(delegation_id)
        if not record or record.get("status") != "running":
            return False
        fn = record.get("interrupt_fn")
    if not callable(fn):
        return False
    try:
        fn()
        logger.info("Interrupted async delegation %s (%s)", delegation_id, reason)
        return True
    except Exception as exc:
        logger.debug("interrupt_delegation: %s interrupt failed: %s", delegation_id, exc)
        return False


def _reset_for_tests() -> None:
    """Test-only: clear all state and tear down the executor."""
    global _executor, _executor_max_workers
    with _executor_lock:
        if _executor is not None:
            _executor.shutdown(wait=False)
        _executor = None
        _executor_max_workers = 0
    with _records_lock:
        _records.clear()
