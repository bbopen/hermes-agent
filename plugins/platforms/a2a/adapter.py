"""
A2A inbound platform adapter — exposes Hermes as an A2A-discoverable agent.

Design (the #11025 insight, done as a plugin with zero core edits):
  - Runs a stdlib http.server in a daemon thread (no a2a-sdk, no asyncio loop
    dependency at register() time — avoids the a2a_fleet "register outside a
    loop" bug class).
  - Serves the Agent Card at GET /.well-known/agent.json.
  - Accepts JSON-RPC ``message/send`` at POST /.
  - Each inbound task is filtered + framed (security.wrap_inbound) and routed
    into the agent's LIVE gateway session via the normal MessageEvent path, so
    the agent that replies is the same one talking to its user — full memory
    and context, not a throwaway clone.
  - The agent's reply comes back through ``adapter.send()``; we override that to
    fulfill a per-context Future the HTTP handler is blocked on, turning the
    async gateway into a synchronous request/response for the A2A caller.
  - Every exchange is persisted to disk and audit-logged.

Bind safety: with no A2A_BEARER_TOKEN, the server binds 127.0.0.1 only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import Future
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)
from gateway.config import Platform
from gateway.session import build_session_key

from . import protocol, security
from .control_plane import (
    ContextAccessDenied,
    ControlPlaneError,
    PayloadConflict,
    TaskAccessDenied,
    TaskStore,
    TERMINAL_STATES,
    canonical_payload_sha256,
    task_to_wire,
)
from .runtime_policy import ActivePolicy, activate, deactivate

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 9900
_REPLY_TIMEOUT = 300  # seconds to wait for the agent to answer an inbound task


class _AgentShuttingDown(RuntimeError):
    pass


class _TaskInterrupted(RuntimeError):
    pass


_SAFE_EXTERNAL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _default_agent_name(extra: Optional[dict] = None) -> str:
    name = str((extra or {}).get("agent_name") or os.getenv("A2A_AGENT_NAME", "")).strip()
    if name:
        return name
    try:
        import socket
        return f"hermes-{socket.gethostname()}"
    except Exception:
        return "hermes-agent"


class A2AAdapter(BasePlatformAdapter):
    """Inbound A2A server adapter."""

    def __init__(self, config, **kwargs):
        platform = Platform("a2a")
        super().__init__(config=config, platform=platform)

        extra = getattr(config, "extra", {}) or {}
        self.port = int(os.getenv("A2A_PORT") or extra.get("port", _DEFAULT_PORT))
        self.host = security.resolve_bind_host(extra)
        self.agent_name = _default_agent_name(extra)
        self.extra = extra
        self.reply_timeout = max(1, int(extra.get("reply_timeout", _REPLY_TIMEOUT)))

        self._httpd: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Durable state is deliberately plugin-owned rather than part of the
        # gateway session cache: task ownership and idempotency must survive a
        # gateway restart without replaying a consequential request.
        self._tasks = TaskStore()

        # Per-context reply futures: an inbound HTTP request blocks on its
        # future until adapter.send() resolves it with the agent's reply.
        self._pending_replies: Dict[str, Future] = {}
        self._pending_tasks: Dict[str, str] = {}
        self._active_tasks: Dict[str, str] = {}
        self._pending_lock = threading.Lock()

    @property
    def name(self) -> str:
        return "A2A"

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def connect(self, **_kwargs) -> bool:
        # Gateway reconnection plumbing passes adapter-agnostic kwargs such as
        # ``is_reconnect``. A2A does not need them, but accepting them keeps the
        # plugin compatible with the BasePlatformAdapter lifecycle contract.
        # Capture the running gateway loop so the HTTP thread can marshal
        # events onto it via run_coroutine_threadsafe.
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

        # Execution itself cannot be resumed safely after a process restart.
        # Reconciliation therefore turns unfinished durable work into one
        # visible terminal result rather than dispatching it again.
        try:
            recovered = self._tasks.reconcile_after_restart()
            for task in recovered:
                security.audit(
                    "recovery", task["principal"], task["task_id"], "",
                    on_behalf_of=task["on_behalf_of"], capability=task["capability"],
                    request_id=task["request_key"], status=task["state"],
                )
        except Exception:
            logger.error("A2A: durable task reconciliation failed", exc_info=True)
            self._set_fatal_error(
                "state_reconciliation_failed",
                "A2A durable task state could not be reconciled safely.",
                retryable=True,
            )
            return False

        adapter = self

        class _Handler(BaseHTTPRequestHandler):
            # Silence the default stderr access log.
            def log_message(self, format, *args):  # noqa: A002,N802
                logger.debug("A2A http: " + format, *args)

            def _json(self, code: int, payload: dict):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                if self.path.rstrip("/") in ("/.well-known/agent.json", "/.well-known/agent-card.json"):
                    self._json(200, adapter._build_card())
                    return
                if self.path.rstrip("/") in ("", "/health"):
                    self._json(200, {"status": "ok", "agent": adapter.agent_name})
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                # Auth (only meaningful when a token is configured; otherwise
                # we are localhost-only by construction).
                identity = security.authenticate_bearer(
                    self.headers.get("Authorization"), adapter.extra
                )
                if identity is None:
                    self._json(401, protocol.jsonrpc_error(None, -32001, "unauthorized"))
                    return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    raw = self.rfile.read(length) if length else b"{}"
                    req = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._json(400, protocol.jsonrpc_error(None, -32700, "parse error"))
                    return

                req_id = req.get("id")
                method = req.get("method", "")
                params = req.get("params", {}) or {}

                if method in ("message/send", "message/stream"):
                    policy, denial = adapter._request_policy(params, identity)
                    if denial:
                        self._json(403, protocol.jsonrpc_error(req_id, -32003, denial))
                        return
                    try:
                        # We answer message/stream as a single (non-streamed) result.
                        result = adapter._handle_inbound_task(params, policy, req_id)
                    except PayloadConflict:
                        self._json(409, protocol.jsonrpc_error(
                            req_id, -32009, "request identity conflicts with an existing payload",
                        ))
                        return
                    except ContextAccessDenied:
                        self._json(403, protocol.jsonrpc_error(
                            req_id, -32003, "context is not authorized for this delegation",
                        ))
                        return
                    except ValueError as e:
                        self._json(400, protocol.jsonrpc_error(req_id, -32602, str(e)))
                        return
                    except ControlPlaneError:
                        logger.warning("A2A: rejected invalid durable task state", exc_info=True)
                        self._json(409, protocol.jsonrpc_error(
                            req_id, -32010, "durable task state is unavailable",
                        ))
                        return
                    self._json(200, protocol.jsonrpc_result(req_id, result))
                    return
                if method == "tasks/get":
                    policy, denial = adapter._request_policy(params, identity)
                    if denial:
                        self._json(403, protocol.jsonrpc_error(req_id, -32003, denial))
                        return
                    task_id = str(params.get("taskId") or params.get("id") or "").strip()
                    if not _SAFE_EXTERNAL_ID.fullmatch(task_id):
                        self._json(400, protocol.jsonrpc_error(req_id, -32602, "valid task id is required"))
                        return
                    try:
                        task = adapter._tasks.get_task(
                            task_id,
                            principal=policy.principal,
                            on_behalf_of=policy.on_behalf_of,
                            capability=policy.capability,
                            enforce_capability=not identity.legacy,
                        )
                    except TaskAccessDenied:
                        self._json(403, protocol.jsonrpc_error(
                            req_id, -32003, "task is not authorized for this delegation",
                        ))
                        return
                    if task is None:
                        self._json(404, protocol.jsonrpc_error(req_id, -32004, "task not found"))
                        return
                    self._json(200, protocol.jsonrpc_result(req_id, task_to_wire(task)))
                    return
                self._json(200, protocol.jsonrpc_error(req_id, -32601, f"method not found: {method}"))

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        except OSError as e:
            logger.error("A2A: could not bind %s:%s — %s", self.host, self.port, e)
            self._set_fatal_error("bind_failed", f"A2A bind failed: {e}", retryable=True)
            return False

        self._server_thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="a2a-http",
            daemon=True,
        )
        self._server_thread.start()
        self._mark_connected()

        exposure = "localhost-only" if security.localhost_only(self.extra) else "REMOTE (bearer auth)"
        logger.info(
            "A2A: serving Agent Card + JSON-RPC on http://%s:%s (%s) as %r",
            self.host, self.port, exposure, self.agent_name,
        )
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        # Fail any in-flight replies so blocked HTTP threads don't hang.
        with self._pending_lock:
            for fut in self._pending_replies.values():
                if not fut.done():
                    fut.set_exception(_AgentShuttingDown("agent shutting down"))
            self._pending_replies.clear()
            self._pending_tasks.clear()
            self._active_tasks.clear()

    # ── Agent Card ────────────────────────────────────────────────────────

    def _build_card(self) -> dict:
        toolsets = []
        try:
            extra = getattr(self.config, "extra", {}) or {}
            toolsets = list(extra.get("advertised_toolsets") or [])
        except Exception:
            pass
        card = protocol.build_agent_card(
            name=self.agent_name,
            url=f"http://{self.host}:{self.port}/",
            description=str(self.extra.get("agent_description") or os.getenv(
                "A2A_AGENT_DESCRIPTION",
                "Hermes Agent — a general-purpose agent reachable over A2A.",
            )),
            skills=protocol.skills_from_toolsets(toolsets),
            streaming=False,
            auth_required=not security.localhost_only(self.extra),
        )
        grants = self.extra.get("capability_tools") or {}
        if isinstance(grants, dict):
            card["x-hermes-capabilities"] = sorted(str(name) for name in grants)
        return card

    # ── Inbound task handling ─────────────────────────────────────────────

    def _request_policy(self, params: dict, identity: security.PeerIdentity):
        message = params.get("message", {}) or {}
        if message and not isinstance(message, dict):
            return None, "message must be an object"
        metadata = message.get("metadata") or params.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None, "metadata must be an object"
        if not identity.legacy and (
            not isinstance(metadata.get("on_behalf_of"), str)
            or not isinstance(metadata.get("capability"), str)
        ):
            return None, "on_behalf_of and capability must be strings"
        on_behalf_of = str(metadata.get("on_behalf_of") or "").strip()
        capability = str(metadata.get("capability") or "").strip()
        denial = security.authorize_claims(identity, on_behalf_of, capability)
        if denial:
            return None, denial

        if identity.legacy:
            allowed_tools = frozenset({"*"})
            tool_rules = None
        else:
            cap_tools = self.extra.get("capability_tools") or {}
            raw_tools = cap_tools.get(capability) if isinstance(cap_tools, dict) else None
            if raw_tools is None:
                return None, "capability has no configured tool grant"
            allowed_tools = frozenset(str(v) for v in raw_tools)
            raw_cap_rules = (self.extra.get("capability_tool_rules") or {}).get(
                capability, {}
            )
            tool_rules = {}
            if isinstance(raw_cap_rules, dict):
                for tool_name, raw_rules in raw_cap_rules.items():
                    if not isinstance(raw_rules, dict):
                        continue
                    tool_rules[str(tool_name)] = {
                        str(field): frozenset(values if isinstance(values, list) else [values])
                        for field, values in raw_rules.items()
                    }

        return ActivePolicy(
            principal=identity.principal,
            on_behalf_of=on_behalf_of,
            capability=capability,
            allowed_tools=allowed_tools,
            tool_rules=tool_rules,
        ), None

    @staticmethod
    def _request_key(params: dict, req_id: Any) -> str:
        message = params.get("message") or {}
        if not isinstance(message, dict):
            return ""
        value = (
            message.get("messageId")
            or params.get("idempotencyKey")
            or req_id
        )
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if not isinstance(value, str):
            return ""
        value = value.strip()
        return value if _SAFE_EXTERNAL_ID.fullmatch(value) else ""

    @staticmethod
    def _context_id(params: dict) -> str:
        message = params.get("message") or {}
        if not isinstance(message, dict):
            raise ValueError("message must be an object")
        value = message.get("contextId") or params.get("contextId") or ""
        if value and (not isinstance(value, str) or not _SAFE_EXTERNAL_ID.fullmatch(value)):
            raise ValueError("contextId must contain only letters, digits, '_' or '-'")
        return str(value or "")

    def _finish_task(
        self,
        task_id: str,
        state: str,
        result: str,
        *,
        policy: ActivePolicy,
        request_id: str,
    ) -> dict:
        stored, emitted = self._tasks.terminalize(task_id, state, security.redact_outbound(result or ""))
        if emitted:
            security.audit(
                "terminal", policy.principal, task_id, "",
                on_behalf_of=policy.on_behalf_of,
                capability=policy.capability,
                request_id=request_id,
                status=stored["state"],
            )
        return stored

    def _wait_for_task(self, task_id: str, timeout: float) -> dict:
        """Wait for the one creator, including a restart-safe poll fallback."""
        until = time.monotonic() + max(0.0, timeout)
        while True:
            task = self._tasks.get_task(task_id, enforce_capability=False)
            if task is None:
                raise ControlPlaneError("durable task state disappeared")
            if task["state"] in TERMINAL_STATES:
                return task
            remaining = until - time.monotonic()
            if remaining <= 0:
                return task
            with self._pending_lock:
                fut = self._pending_replies.get(task["context_id"])
            if fut is not None:
                try:
                    fut.result(timeout=min(remaining, 0.1))
                except Exception:
                    pass
            else:
                time.sleep(min(remaining, 0.05))

    def _handle_inbound_task(self, params: dict, policy: ActivePolicy, req_id: Any) -> dict:
        """Route an inbound A2A task into the live session and wait for reply.

        Runs on an HTTP worker thread. It marshals a MessageEvent onto the
        gateway loop and blocks (on a Future) until adapter.send() fulfils it.
        """
        message = params.get("message") or {}
        if not isinstance(message, dict):
            raise ValueError("message must be an object")
        request_id = self._request_key(params, req_id)
        if not request_id:
            # A fallback generated id would make retries look like unrelated
            # tasks.  Consequential task delivery needs an explicit stable id.
            raise ValueError("messageId or idempotencyKey is required")
        requested_context_id = self._context_id(params)
        text = protocol.extract_text(params)
        peer = policy.principal
        task_id = protocol.new_task_id()
        payload = {
            "method": "message/send",
            "message": message,
            "metadata": params.get("metadata") or {},
        }
        task, created = self._tasks.claim_request(
            principal=policy.principal,
            on_behalf_of=policy.on_behalf_of,
            capability=policy.capability,
            request_key=request_id,
            payload_sha256=canonical_payload_sha256(payload),
            requested_context_id=requested_context_id,
            task_id=task_id,
            deadline_at=None,
        )
        if not created:
            return task_to_wire(self._wait_for_task(task["task_id"], self.reply_timeout))

        task_id = task["task_id"]
        context_id = task["context_id"]

        if not text:
            return task_to_wire(self._finish_task(
                task_id, protocol.STATE_FAILED, "Empty task — nothing to do.",
                policy=policy, request_id=request_id,
            ))

        framed = security.wrap_inbound(
            peer,
            text,
            on_behalf_of=policy.on_behalf_of,
            capability=policy.capability,
        )
        security.audit(
            "inbound", peer, task_id, "",
            on_behalf_of=policy.on_behalf_of,
            capability=policy.capability,
            request_id=request_id,
            status=protocol.STATE_WORKING,
        )
        protocol.persist_message(context_id, "user", text, task_id)

        if self._loop is None or self._message_handler is None:
            return task_to_wire(self._finish_task(
                task_id, protocol.STATE_FAILED, "Agent gateway not ready to accept A2A tasks.",
                policy=policy, request_id=request_id,
            ))

        if not activate(context_id, policy):
            return task_to_wire(self._finish_task(
                task_id, protocol.STATE_FAILED, "Another task is already active for this context.",
                policy=policy, request_id=request_id,
            ))

        fut: Future = Future()
        with self._pending_lock:
            self._pending_replies[context_id] = fut
            self._pending_tasks[context_id] = task_id
            self._active_tasks[task_id] = context_id

        event = MessageEvent(
            text=framed,
            message_type=MessageType.TEXT,
            source=self.build_source(
                chat_id=context_id,
                chat_name=f"a2a:{peer}",
                chat_type="dm",
                user_id=peer,
                user_name=peer,
                # The HTTP edge already bound this identity to a matched peer
                # secret and capability policy.  Mark it authorized so the
                # generic gateway allowlist cannot replace that stronger gate
                # with caller-controlled pairing behavior.
                role_authorized=True,
            ),
            message_id=task_id,
        )

        try:
            asyncio.run_coroutine_threadsafe(self.handle_message(event), self._loop)
        except Exception as e:
            with self._pending_lock:
                self._pending_replies.pop(context_id, None)
                self._pending_tasks.pop(context_id, None)
                self._active_tasks.pop(task_id, None)
            deactivate(context_id)
            return task_to_wire(self._finish_task(
                task_id, protocol.STATE_FAILED, f"Dispatch failed: {e}",
                policy=policy, request_id=request_id,
            ))

        try:
            fut.result(timeout=self.reply_timeout)
        except _AgentShuttingDown:
            self._finish_task(
                task_id, protocol.STATE_FAILED, "[agent shutting down]",
                policy=policy, request_id=request_id,
            )
        except Exception:
            self._finish_task(
                task_id, protocol.STATE_FAILED, "[agent did not reply in time]",
                policy=policy, request_id=request_id,
            )
            # A timeout is an execution boundary, not only an HTTP waiting
            # boundary. Cancel the gateway session so the model cannot keep
            # running tools after the caller has given up and the capability
            # policy has been removed.
            try:
                session_key = build_session_key(
                    event.source,
                    group_sessions_per_user=self.config.extra.get(
                        "group_sessions_per_user", True
                    ),
                    thread_sessions_per_user=self.config.extra.get(
                        "thread_sessions_per_user", False
                    ),
                )
                cancel = asyncio.run_coroutine_threadsafe(
                    self.cancel_session_processing(session_key), self._loop
                )
                cancel.result(timeout=5)
            except Exception:
                logger.warning(
                    "A2A: timed-out session cancellation failed for context %s",
                    context_id,
                    exc_info=True,
                )
        finally:
            with self._pending_lock:
                if self._pending_replies.get(context_id) is fut:
                    self._pending_replies.pop(context_id, None)
                    self._pending_tasks.pop(context_id, None)
                self._active_tasks.pop(task_id, None)
            deactivate(context_id)

        final_task = self._tasks.get_task(task_id, enforce_capability=False)
        if final_task is None:
            raise ControlPlaneError("durable task state disappeared")
        reply = str(final_task.get("result_text") or "")
        protocol.persist_message(context_id, "agent", reply, task_id)
        return task_to_wire(final_task)

    # ── Sending (the agent's reply path) ──────────────────────────────────

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Fulfil the pending reply Future for this context.

        ``chat_id`` is the A2A context id we set as the source chat_id, so it
        keys straight back to the blocked HTTP request.

        The gateway marks final user-visible replies with ``metadata['notify']``.
        Progress, status, and editable preview sends intentionally lack that
        marker; those must not satisfy the JSON-RPC caller, or the caller sees
        a banner/status update instead of the agent's actual answer.
        """
        is_final_reply = bool((metadata or {}).get("notify"))
        with self._pending_lock:
            fut = self._pending_replies.get(chat_id)
            task_id = self._pending_tasks.get(chat_id)
            if fut is not None and not fut.done():
                if not is_final_reply:
                    logger.debug("A2A: ignoring non-final send for context %s", chat_id)
                    return SendResult(success=True, message_id=str(int(time.time() * 1000)))
                if task_id:
                    try:
                        task, emitted = self._tasks.terminalize(
                            task_id, protocol.STATE_COMPLETED,
                            security.redact_outbound(content or ""),
                        )
                    except ControlPlaneError:
                        logger.error("A2A: could not persist final reply for task %s", task_id,
                                     exc_info=True)
                        fut.set_exception(_TaskInterrupted("durable task completion failed"))
                    else:
                        if emitted:
                            fut.set_result(task.get("result_text") or "")
                        else:
                            # A cancellation/deadline/restart has already won
                            # the terminal ledger.  Do not turn it back into a
                            # completion or emit a second notification.
                            fut.set_exception(_TaskInterrupted("task already terminal"))
                else:
                    # Retain the adapter's historical direct-send behavior for
                    # gateway/plugin callers that have no durable A2A task.
                    fut.set_result(content or "")
                return SendResult(success=True, message_id=str(int(time.time() * 1000)))
        # No waiter (e.g. a late streamed chunk or out-of-band send) — drop it.
        logger.debug("A2A: send() for context %s had no pending waiter", chat_id)
        return SendResult(success=True, message_id=str(int(time.time() * 1000)))

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        return None

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": f"a2a:{chat_id}", "type": "dm"}
