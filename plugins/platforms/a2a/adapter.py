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

Bind safety: without active named peer credentials, the created server socket
must be numeric loopback. A legacy local bearer never widens exposure.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import io
import ipaddress
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from concurrent.futures import Future
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
    InvalidTaskState,
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
_DEFAULT_MAX_REQUEST_BYTES = 128 * 1024
_DEFAULT_MAX_INFLIGHT_REQUESTS = 16


class _AgentShuttingDown(RuntimeError):
    pass


class _TaskInterrupted(RuntimeError):
    pass


class _LeaseLost(RuntimeError):
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


def _bounded_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
    try:
        return min(maximum, max(minimum, int(value)))
    except (TypeError, ValueError):
        return default


def _bounded_float(
    value: Any, default: float, *, minimum: float, maximum: float,
) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(parsed):
        return default
    return min(maximum, max(minimum, parsed))


class _AbsoluteDeadlineReader(io.RawIOBase):
    """Socket reader whose timeout is one absolute request deadline."""

    def __init__(self, sock, deadline: float) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("A2A request deadline exceeded")
        self._sock.settimeout(remaining)
        return self._sock.recv_into(buffer)


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound live request workers before stdlib can create unbounded threads."""

    daemon_threads = True

    def __init__(self, *args, max_inflight: int, **kwargs) -> None:
        self._request_slots = threading.BoundedSemaphore(max_inflight)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):  # noqa: D401
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class A2AAdapter(BasePlatformAdapter):
    """Inbound A2A server adapter."""

    def __init__(self, config, **kwargs):
        platform = Platform("a2a")
        super().__init__(config=config, platform=platform)

        extra = getattr(config, "extra", {}) or {}
        self.extra = extra
        from hermes_constants import get_hermes_home

        # HTTP worker threads do not inherit the adapter creation ContextVars.
        # Capture one immutable profile root and reinstall it per request.
        self._profile_home = Path(get_hermes_home())
        self.port = int(extra.get("port") or os.getenv("A2A_PORT") or _DEFAULT_PORT)
        with self._profile_runtime_scope():
            self.host = security.resolve_bind_host(extra)
            self._localhost_only = security.localhost_only(extra)
        self.agent_name = _default_agent_name(extra)
        self.reply_timeout = _bounded_int(
            extra.get("reply_timeout", _REPLY_TIMEOUT),
            _REPLY_TIMEOUT,
            minimum=1,
            maximum=3600,
        )
        self.read_timeout = _bounded_int(
            extra.get("request_timeout", extra.get("read_timeout", 15)),
            15,
            minimum=1,
            maximum=120,
        )
        self.lease_seconds = _bounded_float(
            extra.get("lease_seconds", self.reply_timeout + 15),
            float(self.reply_timeout + 15),
            minimum=30.0,
            maximum=7200.0,
        )
        self.maintenance_interval = _bounded_float(
            extra.get("maintenance_interval", 5), 5.0, minimum=0.25, maximum=60.0,
        )
        self.max_request_bytes = _bounded_int(
            extra.get("max_request_bytes", _DEFAULT_MAX_REQUEST_BYTES),
            _DEFAULT_MAX_REQUEST_BYTES, minimum=1024, maximum=1024 * 1024,
        )
        self.max_inflight_requests = _bounded_int(
            extra.get("max_inflight_requests", _DEFAULT_MAX_INFLIGHT_REQUESTS),
            _DEFAULT_MAX_INFLIGHT_REQUESTS, minimum=1, maximum=128,
        )

        self._httpd: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._maintenance_task: Optional[asyncio.Task] = None

        # Durable state is deliberately plugin-owned rather than part of the
        # gateway session cache: task ownership and idempotency must survive a
        # gateway restart without replaying a consequential request.
        self._tasks = TaskStore(
            self._profile_home / "a2a" / "control-plane" / "tasks.sqlite3"
        )
        self._instance_id = "a2a-" + uuid.uuid4().hex

        # Per-context reply futures: an inbound HTTP request blocks on its
        # future until adapter.send() resolves it with the agent's reply.
        self._pending_replies: Dict[str, Future] = {}
        self._pending_tasks: Dict[str, str] = {}
        self._active_tasks: Dict[str, str] = {}
        self._active_session_keys: Dict[str, str] = {}
        self._dispatch_futures: Dict[str, Future] = {}
        self._lease_heartbeats: Dict[str, float] = {}
        self._pending_lock = threading.Lock()

    @contextmanager
    def _profile_runtime_scope(self):
        """Install the adapter's fixed profile state and fresh secret scope."""
        from hermes_constants import reset_hermes_home_override, set_hermes_home_override
        from agent.secret_scope import (
            build_profile_secret_scope,
            is_multiplex_active,
            reset_secret_scope,
            set_secret_scope,
        )

        home_token = set_hermes_home_override(self._profile_home)
        secret_token = None
        if is_multiplex_active():
            secret_token = set_secret_scope(build_profile_secret_scope(self._profile_home))
        try:
            yield
        finally:
            if secret_token is not None:
                reset_secret_scope(secret_token)
            reset_hermes_home_override(home_token)

    @property
    def name(self) -> str:
        return "A2A"

    def _reconcile_durable_tasks(self) -> list[dict[str, Any]]:
        """Reap stale own leases while protecting handlers with a live heartbeat."""
        now = time.monotonic()
        heartbeat_window = max(1.0, min(10.0, self.lease_seconds * 0.75))
        with self._pending_lock:
            protected = frozenset(
                task_id
                for task_id, heartbeat_at in self._lease_heartbeats.items()
                if now - heartbeat_at <= heartbeat_window
            )
        return self._tasks.reconcile_after_restart(
            exclude_owner=self._instance_id,
            protected_task_ids=protected,
        )

    def _flush_audit_outbox(self, task_id: Optional[str] = None) -> bool:
        """Claim and retry durable audit delivery without concurrent duplication."""
        delivered_all = True
        for _ in range(10):
            events = self._tasks.claim_audit_events(
                owner=self._instance_id,
                task_id=task_id,
                limit=100,
                lease_seconds=max(5.0, self.maintenance_interval * 3),
            )
            if not events:
                break
            for event in events:
                ok = security.audit(
                    event["direction"],
                    event["principal"],
                    event["task_id"],
                    "",
                    on_behalf_of=event["on_behalf_of"],
                    capability=event["capability"],
                    request_id=event["request_id"],
                    status=event["status"],
                    event_id=event["event_id"],
                )
                if ok and security.audit_event_present(event["event_id"]):
                    if not self._tasks.mark_audit_delivered(
                        event["event_id"],
                        owner=self._instance_id,
                        sink_event_id=event["event_id"],
                    ):
                        delivered_all = False
                else:
                    delivered_all = False
                    self._tasks.release_audit_claim(
                        event["event_id"], owner=self._instance_id
                    )
            if not delivered_all:
                break
        pending = self._tasks.pending_audit_events(task_id, limit=100)
        if not pending:
            return delivered_all
        if not delivered_all:
            return False
        # Another synchronous flusher may already own every remaining row.
        # That is durable in-progress delivery, not persistence failure; the
        # claim lease makes it retryable if that flusher exits mid-write.
        now = time.time()
        return all(
            bool(event.get("delivery_owner"))
            and event.get("delivery_expires_at") is not None
            and float(event["delivery_expires_at"]) > now
            for event in pending
        )

    async def _maintenance_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.maintenance_interval)
                with self._profile_runtime_scope():
                    self._reconcile_durable_tasks()
                    self._flush_audit_outbox()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.warning("A2A: maintenance pass failed", exc_info=True)

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
            with self._profile_runtime_scope():
                self._reconcile_durable_tasks()
                self._flush_audit_outbox()
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
            def setup(self):  # noqa: D401
                super().setup()
                # Replace the ordinary inactivity-only socket file with a raw
                # reader that recomputes one absolute header+body deadline on
                # every recv. A one-byte trickle therefore cannot hold a worker
                # slot forever.
                old_rfile = self.rfile
                self.rfile = io.BufferedReader(
                    _AbsoluteDeadlineReader(
                        self.request, time.monotonic() + adapter.read_timeout
                    )
                )
                old_rfile.close()

            def handle_one_request(self):
                with adapter._profile_runtime_scope():
                    return super().handle_one_request()

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
                content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    self._json(415, protocol.jsonrpc_error(None, -32600, "Content-Type must be application/json"))
                    return
                raw_length = self.headers.get("Content-Length")
                if raw_length is None:
                    self._json(411, protocol.jsonrpc_error(None, -32600, "Content-Length is required"))
                    return
                try:
                    length = int(raw_length)
                except (TypeError, ValueError):
                    self._json(400, protocol.jsonrpc_error(None, -32600, "invalid Content-Length"))
                    return
                if length < 1 or length > adapter.max_request_bytes:
                    self.close_connection = True
                    self._json(413, protocol.jsonrpc_error(None, -32600, "request body is too large"))
                    return
                # Auth (only meaningful when a token is configured; otherwise
                # we are localhost-only by construction).
                identity = security.authenticate_bearer(
                    self.headers.get("Authorization"), adapter.extra,
                    self.headers.get("X-A2A-Key-Id"),
                    local_request=security.is_loopback_address(self.client_address[0]),
                )
                if identity is None:
                    self._json(401, protocol.jsonrpc_error(None, -32001, "unauthorized"))
                    return
                try:
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("incomplete request body")
                    req = json.loads(raw.decode("utf-8"))
                except Exception:
                    self._json(400, protocol.jsonrpc_error(None, -32700, "parse error"))
                    return

                if not isinstance(req, dict):
                    self._json(400, protocol.jsonrpc_error(None, -32600, "request must be an object"))
                    return

                req_id = req.get("id")
                method = req.get("method", "")
                params = req.get("params", {}) or {}
                requested_versions = self.headers.get_all("A2A-Version", failobj=[])
                if req.get("jsonrpc") != "2.0":
                    self._json(400, protocol.jsonrpc_error(
                        req_id, -32600, "jsonrpc must be exactly '2.0'",
                    ))
                    return
                if (
                    requested_versions
                    and (
                        len(requested_versions) != 1
                        or requested_versions[0] != protocol.PROTOCOL_VERSION
                    )
                ):
                    self._json(400, protocol.jsonrpc_error(
                        req_id,
                        -32600,
                        "unsupported A2A-Version; supported version is "
                        f"{protocol.PROTOCOL_VERSION}",
                    ))
                    return
                if not isinstance(method, str) or not isinstance(params, dict):
                    self._json(400, protocol.jsonrpc_error(req_id, -32600, "invalid JSON-RPC request"))
                    return
                if method not in protocol.SUPPORTED_METHODS:
                    self._json(200, protocol.jsonrpc_error(
                        req_id, -32601, f"method not found: {method}",
                    ))
                    return

                if method == "message/send":
                    policy, denial = adapter._request_policy(params, identity)
                    if denial:
                        self._json(403, protocol.jsonrpc_error(req_id, -32003, denial))
                        return
                    try:
                        # message/send is the only advertised task-submission method.
                        result = adapter._handle_inbound_task(
                            params, policy, req_id, method=method
                        )
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
                        adapter._reconcile_durable_tasks()
                        task = adapter._tasks.get_task(
                            task_id,
                            principal=policy.principal,
                            on_behalf_of=policy.on_behalf_of,
                            capability=policy.capability,
                            enforce_capability=not identity.local,
                        )
                    except TaskAccessDenied:
                        self._json(404, protocol.jsonrpc_error(req_id, -32004, "task not found"))
                        return
                    if task is None:
                        self._json(404, protocol.jsonrpc_error(req_id, -32004, "task not found"))
                        return
                    adapter._flush_audit_outbox(task_id)
                    self._json(200, protocol.jsonrpc_result(req_id, task_to_wire(task)))
                    return
                if method == "tasks/cancel":
                    policy, denial = adapter._request_policy(params, identity)
                    if denial:
                        self._json(403, protocol.jsonrpc_error(req_id, -32003, denial))
                        return
                    task_id = str(params.get("taskId") or params.get("id") or "").strip()
                    if not _SAFE_EXTERNAL_ID.fullmatch(task_id):
                        self._json(400, protocol.jsonrpc_error(req_id, -32602, "valid task id is required"))
                        return
                    try:
                        task, _changed = adapter._tasks.request_cancel(
                            task_id,
                            principal=policy.principal,
                            on_behalf_of=policy.on_behalf_of,
                            capability=policy.capability,
                            backstop="gateway.cancel_session_processing",
                        )
                    except TaskAccessDenied:
                        self._json(404, protocol.jsonrpc_error(req_id, -32004, "task not found"))
                        return
                    task = adapter._apply_cancellation(task)
                    adapter._flush_audit_outbox(task_id)
                    self._json(200, protocol.jsonrpc_result(req_id, task_to_wire(task)))
                    return
                self._json(200, protocol.jsonrpc_error(req_id, -32601, f"method not found: {method}"))

        try:
            self._httpd = _BoundedThreadingHTTPServer(
                (self.host, self.port), _Handler, max_inflight=self.max_inflight_requests,
            )
        except OSError as e:
            logger.error("A2A: could not bind %s:%s — %s", self.host, self.port, e)
            self._set_fatal_error("bind_failed", f"A2A bind failed: {e}", retryable=True)
            return False

        bound_host, bound_port = self._httpd.server_address[:2]
        self.port = int(bound_port)
        if self._localhost_only and not ipaddress.ip_address(
            str(bound_host).split("%", 1)[0]
        ).is_loopback:
            logger.error(
                "A2A: credentialless/local listener resolved to non-loopback %s; refusing",
                bound_host,
            )
            self._httpd.server_close()
            self._httpd = None
            self._set_fatal_error(
                "unsafe_bind", "A2A local listener did not bind loopback", retryable=False
            )
            return False

        self._server_thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="a2a-http",
            daemon=True,
        )
        self._server_thread.start()
        if self._loop is not None:
            self._maintenance_task = self._loop.create_task(self._maintenance_loop())
        self._mark_connected()

        exposure = "localhost-only" if self._localhost_only else "REMOTE (named peer auth)"
        logger.info(
            "A2A: serving Agent Card + JSON-RPC on http://%s:%s (%s) as %r",
            self.host, self.port, exposure, self.agent_name,
        )
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()
        if self._maintenance_task is not None:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
            self._maintenance_task = None
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
            self._active_session_keys.clear()
            self._dispatch_futures.clear()
            self._lease_heartbeats.clear()

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
            auth_required=security.requires_auth(self.extra),
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

        if identity.local:
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

    @staticmethod
    def _deadline(params: dict) -> Optional[float]:
        """Parse a request deadline as Unix seconds/milliseconds or RFC3339."""
        message = params.get("message") or {}
        metadata = message.get("metadata") if isinstance(message, dict) else None
        metadata = metadata if isinstance(metadata, dict) else {}
        raw = params.get("deadline", metadata.get("deadline"))
        if raw in (None, ""):
            return None
        if isinstance(raw, bool):
            raise ValueError("deadline must be a timestamp")
        if isinstance(raw, (int, float)):
            value = float(raw)
            if not math.isfinite(value):
                raise ValueError("deadline must be finite")
            return value / 1000 if value > 10_000_000_000 else value
        if not isinstance(raw, str):
            raise ValueError("deadline must be a timestamp")
        try:
            try:
                numeric = float(raw)
            except ValueError:
                numeric = None
            if numeric is not None:
                return A2AAdapter._deadline({"deadline": numeric})
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("deadline must include a timezone")
            value = parsed.timestamp()
            if not math.isfinite(value):
                raise ValueError("deadline must be finite")
            return value
        except (ValueError, OverflowError, OSError) as exc:
            raise ValueError("deadline must be Unix time or RFC3339") from exc

    def _interrupt_task(self, task_id: str) -> bool:
        """Interrupt and verify the gateway-owned execution task has exited."""
        with self._pending_lock:
            context_id = self._active_tasks.get(task_id)
            fut = self._pending_replies.get(context_id) if context_id else None
            session_key = self._active_session_keys.get(task_id)
        if self._loop is None:
            return False

        async def _cancel_and_verify() -> bool:
            dispatch = self._dispatch_futures.get(task_id)
            if dispatch is not None and not dispatch.done():
                dispatch.cancel()
                await asyncio.sleep(0)
            if not session_key:
                return False
            session_task = self._session_tasks.get(session_key)
            if session_task is None:
                return False
            if session_task.done():
                return True
            await self.cancel_session_processing(session_key)
            return session_task.done()

        try:
            cancel = asyncio.run_coroutine_threadsafe(
                _cancel_and_verify(), self._loop,
            )
            stopped = bool(cancel.result(timeout=7))
            if stopped and fut is not None and not fut.done():
                fut.set_exception(_TaskInterrupted("task execution stopped"))
            return stopped
        except Exception:
            logger.warning("A2A: gateway cancellation backstop failed for task %s", task_id,
                           exc_info=True)
            return False

    def _apply_cancellation(self, task: dict) -> dict:
        """Apply or retry durable cancellation without overstating success."""
        task_id = str(task["task_id"])
        if task["state"] in TERMINAL_STATES:
            return task
        if task.get("dispatched_at") is None:
            try:
                stored, _ = self._tasks.terminalize_if_not_dispatched(
                    task_id,
                    protocol.STATE_CANCELED,
                    "[task canceled before dispatch]",
                )
                return stored
            except InvalidTaskState:
                return self._tasks.get_task(
                    task_id, enforce_capability=False
                ) or task

        stopped = self._interrupt_task(task_id)
        if stopped:
            try:
                stored, _ = self._tasks.confirm_execution_stopped(
                    task_id,
                    terminal_state=protocol.STATE_CANCELED,
                    result_text="[task canceled by authenticated caller]",
                    lease_owner=self._instance_id,
                    incarnation=int(task["incarnation"]),
                )
                return stored
            except InvalidTaskState:
                return self._tasks.get_task(
                    task_id, enforce_capability=False
                ) or task
        if task.get("lease_owner") == self._instance_id:
            return self._tasks.mark_execution_uncertain(
                task_id, reason="cancel-unconfirmed"
            ) or task
        return task

    def _finish_task(
        self,
        task: dict,
        state: str,
        result: str,
        *,
        allow_uncertain: bool = False,
    ) -> dict:
        stored, emitted = self._tasks.terminalize(
            task["task_id"],
            state,
            security.redact_outbound(result or ""),
            lease_owner=self._instance_id,
            incarnation=int(task["incarnation"]),
            allow_uncertain=allow_uncertain,
        )
        if emitted:
            self._flush_audit_outbox(task["task_id"])
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
            if task.get("deadline_at") is not None:
                until = min(
                    until,
                    time.monotonic() + max(0.0, float(task["deadline_at"]) - time.time()),
                )
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

    def _handle_inbound_task(
        self,
        params: dict,
        policy: ActivePolicy,
        req_id: Any,
        *,
        method: str = "message/send",
    ) -> dict:
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
        deadline_at = self._deadline(params)
        text = protocol.extract_text(params)
        peer = policy.principal
        task_id = protocol.new_task_id()
        # Hash the entire logical method+params envelope, plus normalized
        # effective fields. Future top-level options therefore cannot silently
        # change behavior under an existing message identity.
        payload = {
            "method": method,
            "params": params,
            "effectiveContextId": requested_context_id,
            "effectiveDeadline": deadline_at,
        }
        self._reconcile_durable_tasks()
        task, created = self._tasks.claim_request(
            principal=policy.principal,
            on_behalf_of=policy.on_behalf_of,
            capability=policy.capability,
            request_key=request_id,
            payload_sha256=canonical_payload_sha256(payload),
            requested_context_id=requested_context_id,
            task_id=task_id,
            deadline_at=deadline_at,
            lease_owner=self._instance_id,
            lease_seconds=self.lease_seconds,
        )
        if not created:
            self._reconcile_durable_tasks()
            self._flush_audit_outbox(task["task_id"])
            return task_to_wire(
                self._wait_for_task(task["task_id"], self.reply_timeout)
            )

        task_id = task["task_id"]
        context_id = task["context_id"]

        if not self._flush_audit_outbox(task_id):
            return task_to_wire(self._finish_task(
                task, protocol.STATE_FAILED, "[audit persistence unavailable]"
            ))

        if not text:
            return task_to_wire(self._finish_task(
                task, protocol.STATE_FAILED, "Empty task — nothing to do."
            ))

        if deadline_at is not None and deadline_at <= time.time():
            return task_to_wire(self._finish_task(
                task, protocol.STATE_FAILED, "[task deadline elapsed before dispatch]"
            ))

        framed = security.wrap_inbound(
            peer,
            text,
            on_behalf_of=policy.on_behalf_of,
            capability=policy.capability,
        )
        protocol.persist_message(context_id, "user", text, task_id)

        if self._loop is None or self._message_handler is None:
            return task_to_wire(self._finish_task(
                task,
                protocol.STATE_FAILED,
                "Agent gateway not ready to accept A2A tasks.",
            ))

        if not activate(context_id, policy):
            return task_to_wire(self._finish_task(
                task,
                protocol.STATE_FAILED,
                "Another task is already active for this context.",
            ))

        fut: Future = Future()
        with self._pending_lock:
            self._pending_replies[context_id] = fut
            self._pending_tasks[context_id] = task_id
            self._active_tasks[task_id] = context_id
            self._lease_heartbeats[task_id] = time.monotonic()

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
        session_key = build_session_key(
            event.source,
            group_sessions_per_user=self.config.extra.get("group_sessions_per_user", True),
            thread_sessions_per_user=self.config.extra.get("thread_sessions_per_user", False),
        )
        with self._pending_lock:
            self._active_session_keys[task_id] = session_key

        task, dispatch_allowed = self._tasks.mark_dispatched(
            task_id,
            owner=self._instance_id,
            incarnation=int(task["incarnation"]),
            lease_seconds=self.lease_seconds,
        )
        if not dispatch_allowed:
            with self._pending_lock:
                self._pending_replies.pop(context_id, None)
                self._pending_tasks.pop(context_id, None)
                self._active_tasks.pop(task_id, None)
                self._active_session_keys.pop(task_id, None)
                self._lease_heartbeats.pop(task_id, None)
            deactivate(context_id)
            if task.get("cancel_requested_at") is not None and task.get("dispatched_at") is None:
                task, _ = self._tasks.terminalize_if_not_dispatched(
                    task_id, protocol.STATE_CANCELED, "[task canceled before dispatch]"
                )
                self._flush_audit_outbox(task_id)
            elif task.get("deadline_at") is not None and float(task["deadline_at"]) <= time.time():
                task, _ = self._tasks.terminalize_if_not_dispatched(
                    task_id,
                    protocol.STATE_FAILED,
                    "[task deadline elapsed before dispatch]",
                )
                self._flush_audit_outbox(task_id)
            elif task.get("lease_owner") == self._instance_id:
                task = self._tasks.mark_execution_uncertain(
                    task_id, reason="lease-lost-before-dispatch"
                ) or task
            return task_to_wire(task)

        try:
            dispatch_future = asyncio.run_coroutine_threadsafe(
                self.handle_message(event), self._loop
            )
            with self._pending_lock:
                self._dispatch_futures[task_id] = dispatch_future
        except Exception as e:
            with self._pending_lock:
                self._pending_replies.pop(context_id, None)
                self._pending_tasks.pop(context_id, None)
                self._active_tasks.pop(task_id, None)
                self._active_session_keys.pop(task_id, None)
                self._dispatch_futures.pop(task_id, None)
                self._lease_heartbeats.pop(task_id, None)
            deactivate(context_id)
            return task_to_wire(self._finish_task(
                task, protocol.STATE_FAILED, f"Dispatch failed: {e}"
            ))

        try:
            current = self._tasks.get_task(task_id, enforce_capability=False) or task
            if current.get("cancel_requested_at") is not None:
                self._apply_cancellation(current)

            wait_timeout = float(self.reply_timeout)
            if deadline_at is not None:
                wait_timeout = max(0.0, min(wait_timeout, deadline_at - time.time()))
            if wait_timeout <= 0:
                raise TimeoutError("task deadline elapsed")
            until = time.monotonic() + wait_timeout
            heartbeat = max(0.25, min(5.0, self.lease_seconds / 3.0))
            while True:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("task response deadline elapsed")
                try:
                    fut.result(timeout=min(remaining, heartbeat))
                    break
                except TimeoutError:
                    if fut.done():
                        raise
                    current = self._tasks.get_task(
                        task_id, enforce_capability=False
                    )
                    if current is None:
                        raise _LeaseLost("durable task state disappeared")
                    if current["state"] in TERMINAL_STATES:
                        raise _TaskInterrupted("task became terminal")
                    if current.get("cancel_requested_at") is not None:
                        current = self._apply_cancellation(current)
                        if (
                            current["state"] in TERMINAL_STATES
                            or current.get("execution_uncertain_at") is not None
                        ):
                            raise _TaskInterrupted("durable cancellation consumed")
                    if not self._tasks.renew_lease(
                        task_id,
                        owner=self._instance_id,
                        incarnation=int(task["incarnation"]),
                        lease_seconds=self.lease_seconds,
                    ):
                        raise _LeaseLost("execution lease could not be renewed")
                    with self._pending_lock:
                        self._lease_heartbeats[task_id] = time.monotonic()
        except _AgentShuttingDown:
            self._tasks.request_stop(
                task_id,
                reason="shutdown",
                backstop="gateway.cancel_session_processing",
            )
            self._tasks.mark_execution_uncertain(task_id, reason="shutdown")
        except _TaskInterrupted:
            pass
        except _LeaseLost:
            self._tasks.request_stop(
                task_id,
                reason="lease-lost",
                backstop="gateway.cancel_session_processing",
            )
            self._interrupt_task(task_id)
            self._tasks.mark_execution_uncertain(task_id, reason="lease-lost")
        except TimeoutError:
            is_deadline = deadline_at is not None and deadline_at <= time.time()
            reason = "deadline" if is_deadline else "timeout"
            self._tasks.request_stop(
                task_id,
                reason=reason,
                backstop="gateway.cancel_session_processing",
            )
            stopped = self._interrupt_task(task_id)
            if stopped:
                current = self._tasks.get_task(task_id, enforce_capability=False) or task
                try:
                    self._finish_task(
                        current,
                        protocol.STATE_FAILED,
                        "[task deadline exceeded]"
                        if is_deadline
                        else "[agent did not reply in time]",
                        allow_uncertain=True,
                    )
                except InvalidTaskState:
                    self._tasks.mark_execution_uncertain(
                        task_id, reason=f"{reason}-fence-lost"
                    )
            else:
                self._tasks.mark_execution_uncertain(
                    task_id, reason=f"{reason}-stop-unconfirmed"
                )
        finally:
            with self._pending_lock:
                if self._pending_replies.get(context_id) is fut:
                    self._pending_replies.pop(context_id, None)
                    self._pending_tasks.pop(context_id, None)
                self._active_tasks.pop(task_id, None)
                self._active_session_keys.pop(task_id, None)
                self._dispatch_futures.pop(task_id, None)
                self._lease_heartbeats.pop(task_id, None)
            deactivate(context_id)

        final_task = self._tasks.get_task(task_id, enforce_capability=False)
        if final_task is None:
            raise ControlPlaneError("durable task state disappeared")
        reply = str(final_task.get("result_text") or "")
        if reply:
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
                        current = self._tasks.get_task(
                            task_id, enforce_capability=False
                        )
                        if current is None:
                            raise InvalidTaskState("durable task state disappeared")
                        task, emitted = self._tasks.terminalize(
                            task_id,
                            protocol.STATE_COMPLETED,
                            security.redact_outbound(content or ""),
                            lease_owner=self._instance_id,
                            incarnation=int(current["incarnation"]),
                        )
                    except ControlPlaneError:
                        logger.error("A2A: could not persist final reply for task %s", task_id,
                                     exc_info=True)
                        fut.set_exception(_TaskInterrupted("durable task completion failed"))
                    else:
                        if emitted:
                            self._flush_audit_outbox(task_id)
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
