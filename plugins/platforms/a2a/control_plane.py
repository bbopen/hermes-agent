"""Durable, principal-bound control-plane state for the A2A adapter.

The HTTP adapter is intentionally synchronous at its edge, while the Hermes
gateway is asynchronous.  This module is the small durable authority between
the two: it owns request idempotency, task state transitions, context/task
ownership, cancellation intent, and the one-row terminal-event ledger.

SQLite is used instead of a process-local dict so a restart never turns a
previously accepted consequential request into an unknown request that can be
executed again.  Every write transaction starts with ``BEGIN IMMEDIATE``;
therefore concurrent delivery of the same authenticated request elects one
creator and every other delivery observes that same task.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

from . import protocol


class ControlPlaneError(RuntimeError):
    """Base class for safe-to-return control-plane failures."""


class ContextAccessDenied(ControlPlaneError):
    """A context belongs to another authenticated delegation."""


class TaskAccessDenied(ControlPlaneError):
    """A task belongs to another authenticated delegation."""


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
    protocol.STATE_SUBMITTED: frozenset({protocol.STATE_WORKING, protocol.STATE_FAILED,
                                         protocol.STATE_CANCELED}),
    protocol.STATE_WORKING: frozenset({protocol.STATE_COMPLETED, protocol.STATE_FAILED,
                                       protocol.STATE_CANCELED}),
}


def _hermes_home() -> Path:
    """Resolve the active profile home late so tests and profile changes work."""
    explicit = os.getenv("HERMES_HOME", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home())
    except Exception:
        return Path("~/.hermes").expanduser()


def data_dir() -> Path:
    """Return the plugin-owned durable state directory."""
    return _hermes_home() / "a2a" / "control-plane"


def canonical_payload_sha256(payload: Any) -> str:
    """Hash the complete logical request without retaining its prompt body."""
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _row_to_dict(row: Optional[sqlite3.Row]) -> Optional[dict[str, Any]]:
    if row is None:
        return None
    return dict(row)


class TaskStore:
    """A SQLite-backed task state machine scoped to one Hermes profile."""

    def __init__(self) -> None:
        self._schema_lock = threading.Lock()
        self._initialized_paths: set[str] = set()
        self._ensure_schema()

    @property
    def path(self) -> Path:
        return data_dir() / "tasks.sqlite3"

    def _connect(self) -> sqlite3.Connection:
        self._ensure_schema()
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def _ensure_schema(self) -> None:
        path = self.path
        path_key = str(path)
        with self._schema_lock:
            if path_key in self._initialized_paths:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            conn = sqlite3.connect(path, timeout=10, isolation_level=None)
            try:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous = FULL")
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS contexts (
                        context_id TEXT PRIMARY KEY,
                        principal TEXT NOT NULL,
                        on_behalf_of TEXT NOT NULL,
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
                        cancellation_backstop TEXT NOT NULL DEFAULT '',
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
                    """
                )
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                self._initialized_paths.add(path_key)
            finally:
                conn.close()

    @staticmethod
    def _task(conn: sqlite3.Connection, task_id: str) -> Optional[dict[str, Any]]:
        return _row_to_dict(conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone())

    @staticmethod
    def _assert_context_owner(
        conn: sqlite3.Connection, context_id: str, principal: str, on_behalf_of: str,
    ) -> None:
        row = conn.execute(
            "SELECT principal, on_behalf_of FROM contexts WHERE context_id = ?", (context_id,)
        ).fetchone()
        if row is not None and (
            row["principal"] != principal or row["on_behalf_of"] != on_behalf_of
        ):
            raise ContextAccessDenied("context belongs to a different authenticated delegation")

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
    ) -> tuple[dict[str, Any], bool]:
        """Atomically create or return an idempotent task.

        The boolean is true only for the one delivery entitled to dispatch the
        task.  A duplicate must wait/read the same task and never dispatch it.
        """
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
                    raise PayloadConflict("request identity was reused with a different payload")
                task = self._task(conn, existing["task_id"])
                if task is None:
                    raise InvalidTaskState("request points to missing task state")
                conn.commit()
                return task, False

            context_id = requested_context_id or protocol.new_context_id()
            self._assert_context_owner(conn, context_id, principal, on_behalf_of)
            conn.execute(
                """INSERT OR IGNORE INTO contexts(context_id, principal, on_behalf_of, created_at)
                   VALUES (?, ?, ?, ?)""",
                (context_id, principal, on_behalf_of, now),
            )
            # A concurrent or malformed DB write must not silently reassociate
            # a context after INSERT OR IGNORE.
            self._assert_context_owner(conn, context_id, principal, on_behalf_of)
            conn.execute(
                """INSERT INTO tasks(
                       task_id, context_id, principal, on_behalf_of, capability,
                       request_key, payload_sha256, state, deadline_at, created_at, updated_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    task_id, context_id, principal, on_behalf_of, capability,
                    request_key, payload_sha256, protocol.STATE_SUBMITTED,
                    deadline_at, now, now,
                ),
            )
            conn.execute(
                """INSERT INTO requests(principal, on_behalf_of, request_key, payload_sha256, task_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (principal, on_behalf_of, request_key, payload_sha256, task_id, now),
            )
            conn.execute(
                "UPDATE tasks SET state = ?, updated_at = ? WHERE task_id = ?",
                (protocol.STATE_WORKING, now, task_id),
            )
            task = self._task(conn, task_id)
            conn.commit()
            if task is None:
                raise InvalidTaskState("task state was not persisted")
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
                task["principal"] != principal or task["on_behalf_of"] != (on_behalf_of or "")
            ):
                raise TaskAccessDenied("task belongs to a different authenticated delegation")
            if enforce_capability and capability is not None and task["capability"] != capability:
                raise TaskAccessDenied("task belongs to a different capability grant")
            return task
        finally:
            conn.close()

    def terminalize(self, task_id: str, state: str, result_text: str) -> tuple[dict[str, Any], bool]:
        """Persist one terminal transition and one immutable terminal event.

        A later completion/cancellation notification sees the original task and
        gets ``False``.  It cannot overwrite the result or emit a second event.
        """
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
            permitted = _VALID_TRANSITIONS.get(task["state"], frozenset())
            if state not in permitted:
                raise InvalidTaskState(
                    f"illegal task transition {task['state']} -> {state}"
                )
            conn.execute(
                "UPDATE tasks SET state = ?, result_text = ?, updated_at = ? WHERE task_id = ?",
                (state, result_text or "", now, task_id),
            )
            conn.execute(
                """INSERT OR IGNORE INTO terminal_events(task_id, state, result_sha256, emitted_at)
                   VALUES (?, ?, ?, ?)""",
                (task_id, state, canonical_payload_sha256(result_text or ""), now),
            )
            task = self._task(conn, task_id)
            conn.commit()
            if task is None:
                raise InvalidTaskState("terminal task state was not persisted")
            return task, True
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
        """Durably record cancellation intent and terminally cancel once."""
        now = time.time()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            task = self._task(conn, task_id)
            if task is None:
                raise TaskAccessDenied("task not found or not authorized")
            if (
                task["principal"] != principal
                or task["on_behalf_of"] != on_behalf_of
                or task["capability"] != capability
            ):
                raise TaskAccessDenied("task not found or not authorized")
            if task["state"] in TERMINAL_STATES:
                conn.commit()
                return task, False
            conn.execute(
                """UPDATE tasks SET cancel_requested_at = ?, cancellation_backstop = ?, updated_at = ?
                   WHERE task_id = ?""",
                (now, backstop, now, task_id),
            )
            conn.execute(
                """UPDATE tasks SET state = ?, result_text = ?, updated_at = ? WHERE task_id = ?""",
                (protocol.STATE_CANCELED, "[task canceled by authenticated caller]", now, task_id),
            )
            conn.execute(
                """INSERT OR IGNORE INTO terminal_events(task_id, state, result_sha256, emitted_at)
                   VALUES (?, ?, ?, ?)""",
                (
                    task_id, protocol.STATE_CANCELED,
                    canonical_payload_sha256("[task canceled by authenticated caller]"), now,
                ),
            )
            task = self._task(conn, task_id)
            conn.commit()
            if task is None:
                raise InvalidTaskState("cancellation state was not persisted")
            return task, True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def reconcile_after_restart(self) -> list[dict[str, Any]]:
        """Fail unfinished work safely after a process restart.

        The gateway execution is not serializable.  Re-dispatching a durable
        request after a restart could repeat consequential work, so unfinished
        submissions become one explicit terminal failure instead.
        """
        now = time.time()
        recovered: list[dict[str, Any]] = []
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT * FROM tasks WHERE state IN (?, ?)",
                (protocol.STATE_SUBMITTED, protocol.STATE_WORKING),
            ).fetchall()
            for row in rows:
                task_id = row["task_id"]
                if row["cancel_requested_at"] is not None:
                    state = protocol.STATE_CANCELED
                    result = "[task cancellation recovered after restart]"
                else:
                    state = protocol.STATE_FAILED
                    result = "[task recovery after restart: execution was not resumed]"
                conn.execute(
                    "UPDATE tasks SET state = ?, result_text = ?, updated_at = ? WHERE task_id = ?",
                    (state, result, now, task_id),
                )
                conn.execute(
                    """INSERT OR IGNORE INTO terminal_events(task_id, state, result_sha256, emitted_at)
                       VALUES (?, ?, ?, ?)""",
                    (task_id, state, canonical_payload_sha256(result), now),
                )
                task = self._task(conn, task_id)
                if task is not None:
                    recovered.append(task)
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
                "SELECT COUNT(*) AS count FROM terminal_events WHERE task_id = ?", (task_id,)
            ).fetchone()
            return int(row["count"] if row is not None else 0)
        finally:
            conn.close()


def task_to_wire(task: dict[str, Any]) -> dict[str, Any]:
    """Convert durable task state into the supported A2A task status shape."""
    return protocol.build_task(
        str(task["task_id"]),
        str(task["context_id"]),
        str(task["state"]),
        str(task.get("result_text") or ""),
    )
