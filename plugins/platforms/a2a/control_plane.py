"""Durable, principal-bound control-plane state for the A2A adapter.

SQLite is the authority for request idempotency, context ownership, execution
leases, terminal immutability, and audit delivery. Every mutating operation is
serialized with BEGIN IMMEDIATE so independent adapter instances sharing one
profile cannot both dispatch or complete the same logical request.
"""

from __future__ import annotations

import hashlib
try:
    import fcntl
except ImportError:  # pragma: no cover - native Windows
    fcntl = None  # type: ignore[assignment]
import json
import math
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from . import protocol


class ControlPlaneError(RuntimeError):
    """Base class for safe-to-return control-plane failures."""


class ContextAccessDenied(ControlPlaneError):
    """A context belongs to another authenticated delegation."""


class TaskAccessDenied(ControlPlaneError):
    """A task is absent or belongs to another authenticated delegation."""


class PayloadConflict(ControlPlaneError):
    """A request identity was reused with different canonical data."""


class InvalidTaskState(ControlPlaneError):
    """The durable state does not admit a requested transition."""


TERMINAL_STATES = frozenset({
    protocol.STATE_COMPLETED,
    protocol.STATE_FAILED,
    protocol.STATE_CANCELED,
})

_VALID_TRANSITIONS = {
    protocol.STATE_SUBMITTED: frozenset({
        protocol.STATE_WORKING, protocol.STATE_FAILED, protocol.STATE_CANCELED,
    }),
    protocol.STATE_WORKING: frozenset({
        protocol.STATE_COMPLETED, protocol.STATE_FAILED, protocol.STATE_CANCELED,
    }),
}


def _hermes_home() -> Path:
    """Resolve the active profile home late."""
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        explicit = os.getenv("HERMES_HOME", "").strip()
        return Path(explicit or "~/.hermes").expanduser()


def data_dir() -> Path:
    """Return the plugin-owned durable state directory."""
    return _hermes_home() / "a2a" / "control-plane"


def canonical_payload_sha256(payload: Any) -> str:
    """Hash the complete logical request without retaining its prompt body."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    return None if row is None else dict(row)


class TaskStore:
    """A SQLite-backed task state machine fixed to one Hermes profile."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path is not None else data_dir() / "tasks.sqlite3"
        self._schema_lock = threading.Lock()
        self._initialized = False
        self._ensure_schema()

    @property
    def path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        self._ensure_schema()
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    @staticmethod
    def _add_columns(
        conn: sqlite3.Connection,
        table: str,
        columns: tuple[tuple[str, str], ...],
    ) -> None:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def _ensure_schema(self) -> None:
        with self._schema_lock:
            if self._initialized:
                return
            path = self.path
            if fcntl is None:
                raise ControlPlaneError(
                    "A2A durable state requires cross-process file locking unavailable on this platform"
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            lock_fd = os.open(
                path.with_suffix(path.suffix + ".schema.lock"),
                os.O_CREAT | os.O_RDWR,
                0o600,
            )
            deadline = time.monotonic() + 30.0
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        os.close(lock_fd)
                        raise ControlPlaneError("timed out waiting for schema migration") from exc
                    time.sleep(0.05)
            conn: Optional[sqlite3.Connection] = None
            try:
                conn = sqlite3.connect(path, timeout=30, isolation_level=None)
                conn.execute("PRAGMA busy_timeout = 30000")
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = FULL")
                preexisting_task_columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(tasks)")
                }
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS contexts (
                        context_id TEXT PRIMARY KEY,
                        principal TEXT NOT NULL,
                        on_behalf_of TEXT NOT NULL,
                        capability TEXT NOT NULL DEFAULT '',
                        created_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS tasks (
                        task_id TEXT PRIMARY KEY,
                        context_id TEXT NOT NULL REFERENCES contexts(context_id),
                        principal TEXT NOT NULL,
                        on_behalf_of TEXT NOT NULL,
                        capability TEXT NOT NULL,
                        request_key TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL,
                        result_text TEXT NOT NULL DEFAULT '',
                        deadline_at REAL,
                        cancel_requested_at REAL,
                        deadline_exceeded_at REAL,
                        stop_requested_at REAL,
                        stop_reason TEXT NOT NULL DEFAULT '',
                        execution_uncertain_at REAL,
                        cancellation_backstop TEXT NOT NULL DEFAULT '',
                        dispatched_at REAL,
                        lease_owner TEXT NOT NULL DEFAULT '',
                        lease_expires_at REAL,
                        incarnation INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS tasks_context_idx ON tasks(context_id);

                    CREATE TABLE IF NOT EXISTS requests (
                        principal TEXT NOT NULL,
                        on_behalf_of TEXT NOT NULL,
                        request_key TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        task_id TEXT NOT NULL REFERENCES tasks(task_id),
                        created_at REAL NOT NULL,
                        PRIMARY KEY (principal, on_behalf_of, request_key)
                    );

                    CREATE TABLE IF NOT EXISTS terminal_events (
                        task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
                        state TEXT NOT NULL,
                        result_sha256 TEXT NOT NULL,
                        emitted_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS audit_outbox (
                        event_id TEXT PRIMARY KEY,
                        task_id TEXT NOT NULL REFERENCES tasks(task_id),
                        direction TEXT NOT NULL,
                        principal TEXT NOT NULL,
                        on_behalf_of TEXT NOT NULL,
                        capability TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        last_attempt_at REAL,
                        delivery_owner TEXT NOT NULL DEFAULT '',
                        delivery_expires_at REAL,
                        delivered_at REAL
                    );
                    """
                )
                self._add_columns(conn, "contexts", (("capability", "TEXT NOT NULL DEFAULT ''"),))
                self._add_columns(
                    conn,
                    "tasks",
                    (
                        ("deadline_exceeded_at", "REAL"),
                        ("stop_requested_at", "REAL"),
                        ("stop_reason", "TEXT NOT NULL DEFAULT ''"),
                        ("execution_uncertain_at", "REAL"),
                        ("lease_owner", "TEXT NOT NULL DEFAULT ''"),
                        ("lease_expires_at", "REAL"),
                        ("incarnation", "INTEGER NOT NULL DEFAULT 0"),
                        ("dispatched_at", "REAL"),
                    ),
                )
                self._add_columns(
                    conn,
                    "audit_outbox",
                    (
                        ("last_attempt_at", "REAL"),
                        ("delivery_owner", "TEXT NOT NULL DEFAULT ''"),
                        ("delivery_expires_at", "REAL"),
                    ),
                )
                # Wave-2 working rows predate execution leases and dispatch
                # markers. They may already have reached an agent, so upgrade
                # them as explicitly uncertain rather than treating NULL
                # ``dispatched_at`` as proof that execution never started.
                if preexisting_task_columns and (
                    "lease_expires_at" not in preexisting_task_columns
                    or "dispatched_at" not in preexisting_task_columns
                ):
                    migrated_at = time.time()
                    conn.execute(
                        """UPDATE tasks
                           SET dispatched_at = COALESCE(dispatched_at, updated_at, created_at),
                               execution_uncertain_at = COALESCE(execution_uncertain_at, ?),
                               stop_reason = CASE WHEN stop_reason = ''
                                                  THEN 'legacy-unleased'
                                                  ELSE stop_reason END,
                               updated_at = ?
                           WHERE state = ?""",
                        (migrated_at, migrated_at, protocol.STATE_WORKING),
                    )
                conn.execute(
                    """CREATE INDEX IF NOT EXISTS audit_outbox_pending_idx
                       ON audit_outbox(delivered_at, delivery_expires_at, created_at)"""
                )
                # Wave-2 contexts predate capability binding. Backfill from the
                # first task in each context; a later mismatched capability is
                # then denied instead of silently sharing session history.
                conn.execute(
                    """UPDATE contexts
                       SET capability = COALESCE((
                           SELECT capability FROM tasks
                           WHERE tasks.context_id = contexts.context_id
                           ORDER BY tasks.created_at LIMIT 1
                       ), '')
                       WHERE capability = ''"""
                )
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                self._initialized = True
            finally:
                if conn is not None:
                    conn.close()
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    @staticmethod
    def _task(conn: sqlite3.Connection, task_id: str) -> Optional[dict[str, Any]]:
        return _row_to_dict(conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone())

    @staticmethod
    def _enqueue_audit(
        conn: sqlite3.Connection,
        task: dict[str, Any],
        direction: str,
        status: str,
    ) -> None:
        event_id = f"{task['task_id']}:{direction}:{status}"
        conn.execute(
            """INSERT OR IGNORE INTO audit_outbox(
                   event_id, task_id, direction, principal, on_behalf_of,
                   capability, request_id, status, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                task["task_id"],
                direction,
                task["principal"],
                task["on_behalf_of"],
                task["capability"],
                task["request_key"],
                status,
                time.time(),
            ),
        )

    @staticmethod
    def _assert_context_owner(
        conn: sqlite3.Connection,
        context_id: str,
        principal: str,
        on_behalf_of: str,
        capability: str,
    ) -> None:
        row = conn.execute(
            """SELECT principal, on_behalf_of, capability
               FROM contexts WHERE context_id = ?""",
            (context_id,),
        ).fetchone()
        if row is not None and (
            row["principal"] != principal
            or row["on_behalf_of"] != on_behalf_of
            or row["capability"] != capability
        ):
            raise ContextAccessDenied(
                "context belongs to a different authenticated delegation"
            )

    def claim_request(
        self,
        *,
        principal: str,
        on_behalf_of: str,
        capability: str,
        request_key: str,
        payload_sha256: str,
        requested_context_id: str,
        task_id: str,
        deadline_at: Optional[float],
        lease_owner: str,
        lease_seconds: float,
    ) -> tuple[dict[str, Any], bool]:
        """Create one dispatch claim or return the existing idempotent task."""
        if deadline_at is not None and not math.isfinite(deadline_at):
            raise ValueError("deadline must be finite")
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                """SELECT payload_sha256, task_id FROM requests
                   WHERE principal = ? AND on_behalf_of = ? AND request_key = ?""",
                (principal, on_behalf_of, request_key),
            ).fetchone()
            if existing is not None:
                if existing["payload_sha256"] != payload_sha256:
                    raise PayloadConflict(
                        "request identity was reused with a different payload"
                    )
                task = self._task(conn, existing["task_id"])
                if task is None:
                    raise InvalidTaskState("request points to missing task state")
                conn.commit()
                return task, False

            context_id = requested_context_id or protocol.new_context_id()
            self._assert_context_owner(
                conn, context_id, principal, on_behalf_of, capability
            )
            conn.execute(
                """INSERT OR IGNORE INTO contexts(
                       context_id, principal, on_behalf_of, capability, created_at
                   ) VALUES (?, ?, ?, ?, ?)""",
                (context_id, principal, on_behalf_of, capability, now),
            )
            self._assert_context_owner(
                conn, context_id, principal, on_behalf_of, capability
            )
            unfinished = conn.execute(
                """SELECT task_id FROM tasks
                   WHERE context_id = ? AND state IN (?, ?) LIMIT 1""",
                (context_id, protocol.STATE_SUBMITTED, protocol.STATE_WORKING),
            ).fetchone()
            if unfinished is not None:
                raise InvalidTaskState("context already has an unfinished task")

            incarnation = 1
            conn.execute(
                """INSERT INTO tasks(
                       task_id, context_id, principal, on_behalf_of, capability,
                       request_key, payload_sha256, state, deadline_at,
                       lease_owner, lease_expires_at, incarnation, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id,
                    context_id,
                    principal,
                    on_behalf_of,
                    capability,
                    request_key,
                    payload_sha256,
                    protocol.STATE_WORKING,
                    deadline_at,
                    lease_owner,
                    now + max(1.0, lease_seconds),
                    incarnation,
                    now,
                    now,
                ),
            )
            conn.execute(
                """INSERT INTO requests(
                       principal, on_behalf_of, request_key, payload_sha256, task_id, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (principal, on_behalf_of, request_key, payload_sha256, task_id, now),
            )
            task = self._task(conn, task_id)
            if task is None:
                raise InvalidTaskState("task state was not persisted")
            self._enqueue_audit(conn, task, "inbound", protocol.STATE_WORKING)
            conn.commit()
            return task, True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_task(
        self,
        task_id: str,
        *,
        principal: Optional[str] = None,
        on_behalf_of: Optional[str] = None,
        capability: Optional[str] = None,
        enforce_capability: bool = True,
    ) -> Optional[dict[str, Any]]:
        conn = self._connect()
        try:
            task = self._task(conn, task_id)
            if task is None:
                return None
            if principal is not None and (
                task["principal"] != principal
                or task["on_behalf_of"] != (on_behalf_of or "")
            ):
                raise TaskAccessDenied("task not found")
            if (
                enforce_capability
                and capability is not None
                and task["capability"] != capability
            ):
                raise TaskAccessDenied("task not found")
            return task
        finally:
            conn.close()

    def get_task_by_request(
        self, request_key: str, *, principal: str, on_behalf_of: str, capability: str,
        expected_payload_sha256: str = "",
    ) -> Optional[dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT tasks.* FROM requests JOIN tasks
                     ON requests.task_id = tasks.task_id
                    AND requests.principal = tasks.principal
                    AND requests.on_behalf_of = tasks.on_behalf_of
                    AND requests.request_key = tasks.request_key
                    AND requests.payload_sha256 = tasks.payload_sha256
                   WHERE requests.principal = ? AND requests.on_behalf_of = ?
                     AND requests.request_key = ? AND tasks.capability = ?
                     AND (? = '' OR requests.payload_sha256 = ?)""",
                (
                    principal, on_behalf_of, request_key, capability,
                    expected_payload_sha256, expected_payload_sha256,
                ),
            ).fetchone()
            return _row_to_dict(row)
        finally:
            conn.close()

    @staticmethod
    def _terminalize_locked(
        conn: sqlite3.Connection,
        task: dict[str, Any],
        state: str,
        result_text: str,
        now: float,
    ) -> tuple[dict[str, Any], bool]:
        if task["state"] in TERMINAL_STATES:
            return task, False
        permitted = _VALID_TRANSITIONS.get(task["state"], frozenset())
        if state not in permitted:
            raise InvalidTaskState(
                f"illegal task transition {task['state']} -> {state}"
            )
        conn.execute(
            """UPDATE tasks SET state = ?, result_text = ?, updated_at = ?
               WHERE task_id = ?""",
            (state, result_text or "", now, task["task_id"]),
        )
        conn.execute(
            """INSERT OR IGNORE INTO terminal_events(
                   task_id, state, result_sha256, emitted_at
               ) VALUES (?, ?, ?, ?)""",
            (
                task["task_id"],
                state,
                canonical_payload_sha256(result_text or ""),
                now,
            ),
        )
        stored = TaskStore._task(conn, task["task_id"])
        if stored is None:
            raise InvalidTaskState("terminal task state was not persisted")
        TaskStore._enqueue_audit(conn, stored, "terminal", state)
        return stored, True

    def terminalize(
        self,
        task_id: str,
        state: str,
        result_text: str,
        *,
        lease_owner: str,
        incarnation: int,
        allow_uncertain: bool = False,
    ) -> tuple[dict[str, Any], bool]:
        """Commit a fenced terminal transition for the active execution lease."""
        if state not in TERMINAL_STATES:
            raise InvalidTaskState(f"not a terminal state: {state}")
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None:
                raise InvalidTaskState("unknown task")
            if task["state"] in TERMINAL_STATES:
                conn.commit()
                return task, False
            if (
                task["lease_owner"] != lease_owner
                or int(task["incarnation"]) != int(incarnation)
                or task["lease_expires_at"] is None
                or float(task["lease_expires_at"]) <= now
                or (task["execution_uncertain_at"] is not None and not allow_uncertain)
            ):
                raise InvalidTaskState("execution lease is not active")
            if (
                state == protocol.STATE_COMPLETED
                and task["deadline_at"] is not None
                and float(task["deadline_at"]) <= now
            ):
                raise InvalidTaskState("task deadline has elapsed")
            if state == protocol.STATE_COMPLETED and (
                task["cancel_requested_at"] is not None
                or task["stop_requested_at"] is not None
            ):
                raise InvalidTaskState("task completion is fenced by a stop request")
            stored, emitted = self._terminalize_locked(
                conn, task, state, result_text, now
            )
            conn.commit()
            return stored, emitted
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def terminalize_if_not_dispatched(
        self,
        task_id: str,
        state: str,
        result_text: str,
    ) -> tuple[dict[str, Any], bool]:
        """Terminalize only when durable state proves execution never started."""
        if state not in TERMINAL_STATES:
            raise InvalidTaskState(f"not a terminal state: {state}")
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None:
                raise InvalidTaskState("unknown task")
            if task["state"] in TERMINAL_STATES:
                conn.commit()
                return task, False
            if task["dispatched_at"] is not None:
                raise InvalidTaskState("task may already be executing")
            stored, emitted = self._terminalize_locked(
                conn, task, state, result_text, now
            )
            conn.commit()
            return stored, emitted
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def mark_dispatched(
        self,
        task_id: str,
        *,
        owner: str,
        incarnation: int,
        lease_seconds: float,
    ) -> tuple[dict[str, Any], bool]:
        """Atomically cross the no-execution/execution boundary once."""
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute(
                """UPDATE tasks
                   SET dispatched_at = ?, lease_expires_at = ?, updated_at = ?
                   WHERE task_id = ? AND state = ?
                     AND dispatched_at IS NULL
                     AND cancel_requested_at IS NULL
                     AND execution_uncertain_at IS NULL
                     AND lease_owner = ? AND incarnation = ?
                     AND lease_expires_at > ?
                     AND (deadline_at IS NULL OR deadline_at > ?)""",
                (
                    now,
                    now + max(1.0, lease_seconds),
                    now,
                    task_id,
                    protocol.STATE_WORKING,
                    owner,
                    int(incarnation),
                    now,
                    now,
                ),
            ).rowcount
            task = self._task(conn, task_id)
            conn.commit()
            if task is None:
                raise InvalidTaskState("unknown task")
            return task, bool(updated)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def request_cancel(
        self,
        task_id: str,
        *,
        principal: str,
        on_behalf_of: str,
        capability: str,
        backstop: str,
    ) -> tuple[dict[str, Any], bool]:
        """Record idempotent cancellation intent without claiming it stopped."""
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None or (
                task["principal"] != principal
                or task["on_behalf_of"] != on_behalf_of
                or task["capability"] != capability
            ):
                raise TaskAccessDenied("task not found")
            if task["state"] in TERMINAL_STATES:
                conn.commit()
                return task, False
            changed = task["cancel_requested_at"] is None
            if changed:
                conn.execute(
                    """UPDATE tasks
                       SET cancel_requested_at = ?, stop_requested_at = COALESCE(stop_requested_at, ?),
                           stop_reason = 'cancel', cancellation_backstop = ?, updated_at = ?
                       WHERE task_id = ?""",
                    (now, now, backstop, now, task_id),
                )
            task = self._task(conn, task_id)
            conn.commit()
            if task is None:
                raise InvalidTaskState("cancellation state was not persisted")
            return task, changed
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def request_stop(self, task_id: str, *, reason: str, backstop: str) -> Optional[dict[str, Any]]:
        """Record a deadline/timeout stop request without asserting its outcome."""
        if reason not in {"deadline", "timeout", "shutdown", "lease-lost"}:
            raise ValueError("invalid stop reason")
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None or task["state"] in TERMINAL_STATES:
                conn.commit()
                return task
            conn.execute(
                """UPDATE tasks
                   SET stop_requested_at = COALESCE(stop_requested_at, ?),
                       stop_reason = ?,
                       deadline_exceeded_at = CASE
                           WHEN ? = 'deadline' THEN COALESCE(deadline_exceeded_at, ?)
                           ELSE deadline_exceeded_at END,
                       cancellation_backstop = ?, updated_at = ?
                   WHERE task_id = ?""",
                (now, reason, reason, now, backstop, now, task_id),
            )
            task = self._task(conn, task_id)
            conn.commit()
            return task
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def mark_execution_uncertain(self, task_id: str, *, reason: str) -> Optional[dict[str, Any]]:
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None or task["state"] in TERMINAL_STATES:
                conn.commit()
                return task
            conn.execute(
                """UPDATE tasks
                   SET execution_uncertain_at = COALESCE(execution_uncertain_at, ?),
                       stop_reason = CASE WHEN stop_reason = '' THEN ? ELSE stop_reason END,
                       updated_at = ?
                   WHERE task_id = ?""",
                (now, reason, now, task_id),
            )
            task = self._task(conn, task_id)
            conn.commit()
            return task
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def renew_lease(
        self,
        task_id: str,
        *,
        owner: str,
        incarnation: int,
        lease_seconds: float,
    ) -> bool:
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute(
                """UPDATE tasks SET lease_expires_at = ?, updated_at = ?
                   WHERE task_id = ? AND state = ?
                     AND lease_owner = ? AND incarnation = ?
                     AND lease_expires_at > ?
                     AND execution_uncertain_at IS NULL""",
                (
                    now + max(1.0, lease_seconds),
                    now,
                    task_id,
                    protocol.STATE_WORKING,
                    owner,
                    int(incarnation),
                    now,
                ),
            ).rowcount
            conn.commit()
            return bool(updated)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def confirm_execution_stopped(
        self,
        task_id: str,
        *,
        terminal_state: str,
        result_text: str,
        lease_owner: str,
        incarnation: int,
    ) -> tuple[dict[str, Any], bool]:
        return self.terminalize(
            task_id,
            terminal_state,
            result_text,
            lease_owner=lease_owner,
            incarnation=incarnation,
            allow_uncertain=True,
        )

    def reconcile_after_restart(
        self,
        *,
        exclude_owner: str = "",
        protected_task_ids: frozenset[str] = frozenset(),
    ) -> list[dict[str, Any]]:
        """Fence expired foreign executions without replaying or inventing success."""
        now = time.time()
        recovered: list[dict[str, Any]] = []
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            query = """SELECT * FROM tasks
                       WHERE state = ?
                         AND ((deadline_at IS NOT NULL AND deadline_at <= ?)
                              OR (lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                              OR (lease_expires_at IS NULL
                                  AND execution_uncertain_at IS NULL))"""
            params: list[Any] = [protocol.STATE_WORKING, now, now]
            if exclude_owner and protected_task_ids:
                placeholders = ",".join("?" for _ in protected_task_ids)
                query += f" AND NOT (lease_owner = ? AND task_id IN ({placeholders}))"
                params.extend([exclude_owner, *sorted(protected_task_ids)])
            rows = conn.execute(query, params).fetchall()
            for row in rows:
                task = dict(row)
                deadline_due = task["deadline_at"] is not None and float(task["deadline_at"]) <= now
                if task["lease_expires_at"] is None:
                    conn.execute(
                        """UPDATE tasks SET
                               dispatched_at = COALESCE(dispatched_at, updated_at, created_at, ?),
                               deadline_exceeded_at = CASE
                                   WHEN ? THEN COALESCE(deadline_exceeded_at, ?)
                                   ELSE deadline_exceeded_at END,
                               stop_reason = CASE WHEN ? THEN 'deadline'
                                                  WHEN stop_reason = '' THEN 'lease-missing'
                                                  ELSE stop_reason END,
                               execution_uncertain_at = COALESCE(execution_uncertain_at, ?),
                               updated_at = ?
                           WHERE task_id = ?""",
                        (
                            now,
                            deadline_due,
                            now,
                            deadline_due,
                            now,
                            now,
                            task["task_id"],
                        ),
                    )
                    stored = self._task(conn, task["task_id"])
                    if stored is not None:
                        recovered.append(stored)
                    continue
                if task["dispatched_at"] is None:
                    if task["cancel_requested_at"] is not None:
                        stored, _ = self._terminalize_locked(
                            conn,
                            task,
                            protocol.STATE_CANCELED,
                            "[task canceled before dispatch]",
                            now,
                        )
                        recovered.append(stored)
                        continue
                    result = (
                        "[task deadline elapsed before dispatch]"
                        if deadline_due
                        else "[task abandoned before dispatch]"
                    )
                    if deadline_due:
                        conn.execute(
                            """UPDATE tasks SET deadline_exceeded_at = COALESCE(deadline_exceeded_at, ?),
                                   stop_requested_at = COALESCE(stop_requested_at, ?),
                                   stop_reason = 'deadline', updated_at = ? WHERE task_id = ?""",
                            (now, now, now, task["task_id"]),
                        )
                        task = self._task(conn, task["task_id"]) or task
                    stored, _ = self._terminalize_locked(
                        conn, task, protocol.STATE_FAILED, result, now
                    )
                    recovered.append(stored)
                    continue
                conn.execute(
                    """UPDATE tasks SET
                           deadline_exceeded_at = CASE
                               WHEN ? THEN COALESCE(deadline_exceeded_at, ?) ELSE deadline_exceeded_at END,
                           stop_reason = CASE WHEN ? THEN 'deadline'
                                              WHEN stop_reason = '' THEN 'lease-expired'
                                              ELSE stop_reason END,
                           execution_uncertain_at = COALESCE(execution_uncertain_at, ?),
                           updated_at = ?
                       WHERE task_id = ?""",
                    (deadline_due, now, deadline_due, now, now, task["task_id"]),
                )
                stored = self._task(conn, task["task_id"])
                if stored is not None:
                    recovered.append(stored)
            conn.commit()
            return recovered
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def terminal_event_count(self, task_id: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS count FROM terminal_events WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            return int(row["count"] if row is not None else 0)
        finally:
            conn.close()

    def claim_audit_events(
        self,
        *,
        owner: str,
        task_id: Optional[str] = None,
        limit: int = 100,
        lease_seconds: float = 30.0,
    ) -> list[dict[str, Any]]:
        """Claim pending audit deliveries so concurrent flushers do not duplicate them."""
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            where = """delivered_at IS NULL
                       AND (delivery_owner = ''
                            OR delivery_expires_at IS NULL OR delivery_expires_at <= ?)"""
            params: list[Any] = [now]
            if task_id:
                where += " AND task_id = ?"
                params.append(task_id)
            params.append(max(1, int(limit)))
            rows = conn.execute(
                f"""SELECT event_id FROM audit_outbox WHERE {where}
                    ORDER BY created_at, event_id LIMIT ?""",
                params,
            ).fetchall()
            event_ids = [row["event_id"] for row in rows]
            for event_id in event_ids:
                conn.execute(
                    """UPDATE audit_outbox
                       SET delivery_owner = ?, delivery_expires_at = ?,
                           attempts = attempts + 1, last_attempt_at = ?
                       WHERE event_id = ? AND delivered_at IS NULL
                         AND (delivery_owner = ''
                              OR delivery_expires_at IS NULL OR delivery_expires_at <= ?)""",
                    (
                        owner,
                        now + max(1.0, lease_seconds),
                        now,
                        event_id,
                        now,
                    ),
                )
            if not event_ids:
                conn.commit()
                return []
            placeholders = ",".join("?" for _ in event_ids)
            claimed = conn.execute(
                f"""SELECT * FROM audit_outbox
                    WHERE event_id IN ({placeholders}) AND delivery_owner = ?
                    ORDER BY created_at, event_id""",
                [*event_ids, owner],
            ).fetchall()
            conn.commit()
            return [dict(row) for row in claimed]
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def mark_audit_delivered(
        self, event_id: str, *, owner: str, sink_event_id: str = ""
    ) -> bool:
        if not event_id or sink_event_id != event_id:
            return False
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute(
                """UPDATE audit_outbox
                   SET delivered_at = ?, delivery_owner = '', delivery_expires_at = NULL
                   WHERE event_id = ? AND delivery_owner = ? AND delivered_at IS NULL""",
                (time.time(), event_id, owner),
            ).rowcount
            conn.commit()
            return bool(updated)
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def release_audit_claim(self, event_id: str, *, owner: str) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE audit_outbox
                   SET delivery_owner = '', delivery_expires_at = NULL
                   WHERE event_id = ? AND delivery_owner = ? AND delivered_at IS NULL""",
                (event_id, owner),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def pending_audit_events(
        self, task_id: Optional[str] = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if task_id:
                rows = conn.execute(
                    """SELECT * FROM audit_outbox
                       WHERE delivered_at IS NULL AND task_id = ?
                       ORDER BY created_at, event_id LIMIT ?""",
                    (task_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM audit_outbox WHERE delivered_at IS NULL
                       ORDER BY created_at, event_id LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def terminal_delivery_state(self, task_id: str) -> Optional[str]:
        conn = self._connect()
        try:
            row = conn.execute(
                """SELECT delivered_at FROM audit_outbox
                   WHERE task_id = ? AND direction = 'terminal'
                   ORDER BY created_at DESC LIMIT 1""",
                (task_id,),
            ).fetchone()
            if row is None:
                return None
            return "delivered" if row["delivered_at"] is not None else "pending"
        finally:
            conn.close()


def task_to_wire(task: dict[str, Any]) -> dict[str, Any]:
    """Convert durable task state into a stable supported A2A task shape."""
    from .security import safe_structured_identifier

    wire = protocol.build_task(
        safe_structured_identifier(task["task_id"]),
        safe_structured_identifier(task["context_id"]),
        str(task["state"]),
        str(task.get("result_text") or ""),
        timestamp=float(task.get("updated_at") or task.get("created_at") or time.time()),
    )
    control: dict[str, Any] = {}
    if task.get("cancel_requested_at") is not None:
        control["cancellation"] = "requested"
    if task.get("deadline_exceeded_at") is not None:
        control["deadline"] = "exceeded"
    if task.get("execution_uncertain_at") is not None:
        control["execution"] = "uncertain"
    if control and task["state"] not in TERMINAL_STATES:
        wire["x-hermes-control"] = control
    return wire
