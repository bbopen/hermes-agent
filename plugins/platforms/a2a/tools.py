"""
A2A client tools — let the Hermes agent talk to *other* agents as a peer.

Tools (registered in the ``a2a`` toolset):
  - a2a_discover(url)        -> fetch + summarize a peer's Agent Card
  - a2a_call(agent, message) -> send a task to a peer, return its reply
  - a2a_list()               -> list configured peers + persisted conversations

Peers are resolved from config.yaml under ``a2a_agents``::

    a2a_agents:
      researcher:
        url: "http://localhost:9999"
        auth: { type: bearer, key_env: "RESEARCHER_A2A_TOKEN" }
        on_behalf_of: "brett"
        capability: "research.read"
        timeout: 120

Transport is stdlib urllib (no a2a-sdk dependency). The wire format is the A2A
JSON-RPC ``message/send`` method, so any A2A-compliant peer works.
"""

from __future__ import annotations

import json
import http.client
import io
import ipaddress
import logging
import math
import os
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from typing import Any, Optional

from . import protocol, security

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 120
_MAX_OUTBOUND_REQUEST_BYTES = 256 * 1024
_MAX_OUTBOUND_RESPONSE_BYTES = 512 * 1024


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("A2A request deadline exceeded")
    return remaining


def _resolve_addresses(host: str, port: int, deadline: float):
    """Bound blocking getaddrinfo with a daemon resolver handoff."""
    result: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put((True, socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except Exception as exc:
            result.put((False, exc))

    threading.Thread(target=resolve, name="a2a-dns", daemon=True).start()
    try:
        ok, value = result.get(timeout=_remaining(deadline))
    except queue.Empty as exc:
        raise TimeoutError("peer DNS resolution exceeded request deadline") from exc
    if not ok:
        raise value
    return value


class _DeadlineRawReader(io.RawIOBase):
    def __init__(self, sock, deadline: float) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self._sock.settimeout(_remaining(self._deadline))
        return self._sock.recv_into(buffer)


class _DeadlineSocketView:
    """HTTPResponse socket view that applies one absolute read deadline."""

    def __init__(self, sock, deadline: float) -> None:
        self._sock = sock
        self._deadline = deadline

    def makefile(self, mode="rb", buffering=None):
        if mode != "rb":
            raise ValueError("deadline socket view is read-only")
        return io.BufferedReader(_DeadlineRawReader(self._sock, self._deadline))


def _pinned_addresses(
    url: str, deadline: Optional[float] = None,
) -> tuple[object, tuple, str, int, str]:
    """Resolve once, validate that address set, and return one connect target.

    Validation and TCP connection deliberately share this resolution result so
    a DNS rebinding response cannot turn a previously-safe hostname into an
    internal connection between checking and use.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    scheme = parts.scheme
    port = parts.port or (443 if scheme == "https" else 80)
    deadline = deadline or (time.monotonic() + _DEFAULT_TIMEOUT)
    allow_private = _configured_origin_allowed(url, _load_config())
    try:
        parsed = ipaddress.ip_address(host)
        addresses = [(
            socket.AF_INET6 if parsed.version == 6 else socket.AF_INET,
            (str(parsed), port, 0, 0) if parsed.version == 6 else (str(parsed), port),
        )]
    except ValueError:
        try:
            infos = _resolve_addresses(host, port, deadline)
        except OSError as exc:
            raise ValueError(f"peer host could not be resolved safely: {host}") from exc
        addresses = [(family, sockaddr) for family, _, _, _, sockaddr in infos]
    if not addresses:
        raise ValueError(f"peer host could not be resolved safely: {host}")
    parsed_addresses = [
        ipaddress.ip_address(str(address[1][0]).split("%", 1)[0])
        for address in addresses
    ]
    if any(not address.is_global for address in parsed_addresses) and not allow_private:
        raise ValueError("private, loopback, link-local, or internal peer URLs require explicit configuration")
    family, sockaddr = addresses[0]
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return family, sockaddr, host, port, path


def _pinned_json_request(
    method: str,
    url: str,
    headers: dict,
    timeout: float,
    data: bytes = b"",
) -> dict:
    """Perform a bounded HTTP request through the validated resolved socket."""
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("peer timeout must be a positive finite number")
    deadline = time.monotonic() + timeout
    family, sockaddr, host, port, path = _pinned_addresses(url, deadline)
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(sockaddr)
        if urlsplit(url).scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
            sock.settimeout(_remaining(deadline))
        display_host = f"[{host}]" if ":" in host else host
        request_headers = {
            "Host": display_host if port in (80, 443) else f"{display_host}:{port}",
            "Connection": "close",
            **headers,
        }
        if data:
            request_headers.setdefault("Content-Length", str(len(data)))
        for name, value in request_headers.items():
            if not name or any(char in str(name) for char in "\r\n:"):
                raise ValueError("invalid outbound HTTP header name")
            if any(char in str(value) for char in "\r\n"):
                raise ValueError("invalid outbound HTTP header value")
        lines = [f"{method} {path} HTTP/1.1"]
        lines.extend(f"{name}: {value}" for name, value in request_headers.items())
        sock.settimeout(_remaining(deadline))
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + data)
        response = http.client.HTTPResponse(_DeadlineSocketView(sock, deadline))
        response.begin()
        if 300 <= response.status < 400:
            raise urllib.error.HTTPError(url, response.status, "A2A redirects are rejected", response.headers, response)
        if response.status >= 400:
            raise urllib.error.HTTPError(url, response.status, response.reason, response.headers, response)
        raw = response.read(_MAX_OUTBOUND_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_OUTBOUND_RESPONSE_BYTES:
            raise ValueError("peer response is too large")
        return json.loads(raw.decode("utf-8"))
    finally:
        try:
            sock.close()
        except OSError:
            pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow an A2A redirect with or without a bearer credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        raise urllib.error.HTTPError(req.full_url, code, "A2A redirects are rejected", headers, fp)


def _origin(url: str) -> str:
    """Return a canonical http(s) origin or reject ambiguous peer URLs."""
    parts = urlsplit(str(url or "").strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("peer URL must be an absolute http(s) URL")
    if parts.username or parts.password:
        raise ValueError("peer URL must not contain userinfo")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("peer URL has an invalid port") from exc
    host = parts.hostname.lower().rstrip(".")
    return f"{parts.scheme}://{host}:{port}"


def _is_non_public_host(host: str) -> bool:
    """Classify syntactically local destinations without resolving DNS.

    Hostname resolution is deliberately deferred to _pinned_addresses, where
    the validated result is the exact sockaddr used by connect().
    """
    lowered = host.lower().rstrip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith(
        (".localhost", ".local", ".internal")
    ) or "." not in lowered:
        return True
    try:
        return not ipaddress.ip_address(lowered).is_global
    except ValueError:
        return False


def _validate_peer_url(
    url: str,
    *,
    expected_origin: Optional[str] = None,
    allow_configured_non_public: bool = False,
) -> str:
    """Pin a peer URL to its configured origin before issuing HTTP."""
    actual_origin = _origin(url)
    if expected_origin is not None and actual_origin != expected_origin:
        raise ValueError("peer URL changed origin; refusing credential forwarding")
    host = urlsplit(url).hostname or ""
    if _is_non_public_host(host) and not allow_configured_non_public:
        raise ValueError("private, loopback, link-local, or internal peer URLs require explicit configuration")
    return actual_origin


def _configured_origin_allowed(url: str, cfg: dict) -> bool:
    """True only when this exact origin is already named in config.yaml."""
    try:
        target = _origin(url)
    except ValueError:
        return False
    peers = cfg.get("a2a_agents") or {}
    if not isinstance(peers, dict):
        return False
    for entry in peers.values():
        if not isinstance(entry, dict):
            continue
        try:
            if _origin(str(entry.get("url") or "")) == target:
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------
# Peer resolution
# --------------------------------------------------------------------------

def _load_config() -> dict:
    try:
        from hermes_cli.config import load_config
        return load_config() or {}
    except Exception:
        return {}


def _resolve_peer(agent: str) -> Optional[dict]:
    """Resolve a peer name to {url, auth, timeout}, or treat ``agent`` as a URL."""
    if agent.startswith("http://") or agent.startswith("https://"):
        return {"url": agent, "auth": {}, "timeout": _DEFAULT_TIMEOUT, "configured": False}
    cfg = _load_config()
    peers = cfg.get("a2a_agents") or {}
    entry = peers.get(agent)
    if not entry:
        return None
    try:
        timeout = float(entry.get("timeout", _DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = float(_DEFAULT_TIMEOUT)
    if not math.isfinite(timeout) or timeout <= 0:
        timeout = float(_DEFAULT_TIMEOUT)
    return {
        "url": entry.get("url", ""),
        "auth": entry.get("auth", {}) or {},
        "timeout": min(timeout, 3600.0),
        "on_behalf_of": str(entry.get("on_behalf_of") or ""),
        "capability": str(entry.get("capability") or ""),
        "configured": True,
    }


def _auth_header(auth: dict) -> dict:
    if auth and auth.get("type") == "bearer":
        key_env = str(auth.get("key_env") or "").strip()
        token = security._credential_value(key_env) if key_env else ""
        # Legacy plaintext config remains readable for compatibility, but new
        # configurations must use key_env so secrets stay in the profile .env.
        token = token or str(auth.get("token") or "").strip()
        if token:
            headers = {"Authorization": f"Bearer {token}"}
            key_id = str(auth.get("key_id") or auth.get("credential_id") or "").strip()
            if key_id:
                headers["X-A2A-Key-Id"] = key_id
            return headers
    return {}


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

def _http_get_json(url: str, headers: dict, timeout: float) -> dict:
    return _pinned_json_request("GET", url, headers, timeout)


def _http_post_json(url: str, body: dict, headers: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    if len(data) > _MAX_OUTBOUND_REQUEST_BYTES:
        raise ValueError("A2A request is too large")
    return _pinned_json_request("POST", url, {"Content-Type": "application/json", **headers}, timeout, data)


def _card_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/.well-known/agent.json"


def _rpc_url(base_url: str, card: Optional[dict]) -> str:
    # Prefer the URL the card advertises; fall back to the base.
    if card and isinstance(card.get("url"), str) and card["url"]:
        return card["url"]
    return base_url.rstrip("/")


# --------------------------------------------------------------------------
# Tool handlers
# --------------------------------------------------------------------------

def a2a_discover(args: dict, **_: Any) -> str:
    """Fetch and summarize the Agent Card at ``url``."""
    url = str(args.get("url") or "").strip()
    if not url:
        return "Error: 'url' is required (e.g. http://localhost:9999)."
    cfg = _load_config()
    try:
        origin = _origin(url)
        allow_private = _configured_origin_allowed(url, cfg)
        _validate_peer_url(
            url, expected_origin=origin, allow_configured_non_public=allow_private,
        )
    except ValueError as e:
        return f"Error: unsafe peer URL — {e}."
    try:
        card = _http_get_json(_card_url(url), {}, _DEFAULT_TIMEOUT)
    except urllib.error.HTTPError as e:
        return f"Error: discovery failed — HTTP {e.code} from {url}."
    except Exception as e:
        return f"Error: could not reach {url} — {e}."

    if not isinstance(card, dict):
        return "Error: peer returned an invalid Agent Card."
    advertised = card.get("url")
    if advertised:
        try:
            _validate_peer_url(
                str(advertised), expected_origin=origin,
                allow_configured_non_public=allow_private,
            )
        except ValueError as e:
            return f"Error: peer Agent Card was rejected — {e}."

    name = card.get("name", "?")
    desc = card.get("description", "")
    caps = card.get("capabilities", {}) or {}
    skills = card.get("skills", []) or []
    grants = card.get("x-hermes-capabilities", []) or []
    auth = "yes" if card.get("security") else "no"
    lines = [
        f"Agent: {name}",
        f"Description: {desc}",
        f"URL: {card.get('url', url)}",
        f"Streaming: {bool(caps.get('streaming'))}  Auth required: {auth}",
        f"Skills ({len(skills)}):",
    ]
    for s in skills[:20]:
        lines.append(f"  - {s.get('name', s.get('id', '?'))}: {s.get('description', '')}")
    if grants:
        lines.append("Hermes capabilities: " + ", ".join(str(v) for v in grants))
    return "\n".join(lines)


def a2a_call(args: dict, **_: Any) -> str:
    """Send a task to a peer agent and return its reply.

    ``agent`` is a configured peer name (from ``a2a_agents``) or a direct URL.
    ``context_id`` continues a prior exchange (multi-turn) when provided.
    """
    # Accept common aliases models reach for (observed live: 'agent_name').
    agent = str(args.get("agent") or args.get("agent_name") or args.get("name") or "").strip()
    message = str(args.get("message") or args.get("text") or args.get("task") or "").strip()
    context_id = str(args.get("context_id") or args.get("contextId") or "").strip()
    on_behalf_of = str(args.get("on_behalf_of") or "").strip()
    capability = str(args.get("capability") or "").strip()
    if not agent or not message:
        return "Error: both 'agent' and 'message' are required."

    peer = _resolve_peer(agent)
    if not peer or not peer.get("url"):
        return (
            f"Error: unknown agent '{agent}'. Configure it under 'a2a_agents' in "
            f"config.yaml or pass a full http(s):// URL."
        )

    base_url = peer["url"]
    try:
        peer_origin = _origin(base_url)
        _validate_peer_url(
            base_url,
            expected_origin=peer_origin,
            allow_configured_non_public=bool(peer.get("configured")),
        )
    except ValueError as e:
        return f"Error: unsafe peer URL — {e}."
    headers = _auth_header(peer["auth"])
    try:
        timeout = float(peer["timeout"])
    except (TypeError, ValueError):
        return f"Error: peer '{agent}' has an invalid request timeout."
    if not math.isfinite(timeout) or timeout <= 0:
        return f"Error: peer '{agent}' has an invalid request timeout."
    timeout = min(timeout, 3600.0)
    request_deadline = time.monotonic() + timeout
    on_behalf_of = on_behalf_of or peer.get("on_behalf_of", "")
    capability = capability or peer.get("capability", "")

    ctx = context_id or protocol.new_context_id()
    safe_message = security.redact_outbound(message)
    rpc_body = {
        "jsonrpc": "2.0",
        "id": protocol.new_task_id(),
        "method": "message/send",
        "params": {
            "message": protocol.text_message("user", safe_message),
            "deadline": time.time() + timeout,
        },
    }
    rpc_body["params"]["message"]["metadata"] = {
        "on_behalf_of": on_behalf_of,
        "capability": capability,
    }
    if context_id:
        rpc_body["params"]["message"]["contextId"] = context_id
    if not security.audit(
        "outbound",
        agent,
        rpc_body["id"],
        safe_message,
        on_behalf_of=on_behalf_of,
        capability=capability,
        request_id=rpc_body["params"]["message"]["messageId"],
        status="submitted",
    ):
        return "Error: outbound audit persistence is unavailable; request was not sent."

    # Best-effort card fetch (to learn the rpc URL); non-fatal on failure.
    card = None
    try:
        card = _http_get_json(
            _card_url(base_url), headers, min(_remaining(request_deadline), 30.0)
        )
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return f"Error: peer '{agent}' redirected its Agent Card; redirects are refused."
    except Exception:
        pass

    if card is not None and not isinstance(card, dict):
        return f"Error: peer '{agent}' returned an invalid Agent Card."
    try:
        rpc_url = _rpc_url(base_url, card)
        _validate_peer_url(
            rpc_url,
            expected_origin=peer_origin,
            allow_configured_non_public=bool(peer.get("configured")),
        )
    except ValueError as e:
        return f"Error: peer '{agent}' Agent Card was rejected — {e}."

    try:
        peer_remaining = _remaining(request_deadline)
    except TimeoutError:
        return f"Error: call to '{agent}' exceeded its request deadline."
    rpc_body["params"]["deadline"] = time.time() + peer_remaining
    protocol.persist_message(ctx, "user", safe_message, rpc_body["id"])

    try:
        # The credential-bearing request is issued only after the final RPC
        # target has passed the exact configured-origin pin above.
        resp = _http_post_json(
            rpc_url, rpc_body, headers, _remaining(request_deadline)
        )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return f"Error: peer '{agent}' rejected auth (HTTP {e.code}). Check the configured token."
        return f"Error: call to '{agent}' failed — HTTP {e.code}."
    except Exception as e:
        return f"Error: call to '{agent}' failed — {e}."

    if "error" in resp:
        err = resp["error"]
        return f"Peer '{agent}' returned an error: {err.get('message', err)}"

    result = resp.get("result", {})
    reply = _reply_text_from_result(result)
    reply_ctx = result.get("contextId", ctx) if isinstance(result, dict) else ctx
    protocol.persist_message(reply_ctx, "agent", reply, rpc_body["id"])

    state = ""
    if isinstance(result, dict):
        state = (result.get("status") or {}).get("state", "")
    header = f"[{agent} · context {reply_ctx}"
    if state:
        header += f" · {state}"
    header += "]"
    return f"{header}\n{reply or '(no text reply)'}"


def _reply_text_from_result(result: Any) -> str:
    if not isinstance(result, dict):
        return str(result)
    # Artifacts first (final output), then status message (interim/clarify).
    for artifact in result.get("artifacts", []) or []:
        txt = protocol.extract_text(artifact)
        if txt:
            return txt
    status = result.get("status", {}) or {}
    msg = status.get("message")
    if msg:
        return protocol.extract_text(msg)
    # Bare message result (message/send may return a Message instead of a Task)
    return protocol.extract_text(result)


def a2a_list(args: dict | None = None, **_: Any) -> str:
    """List configured A2A peers and any persisted conversations."""
    cfg = _load_config()
    peers = cfg.get("a2a_agents") or {}
    lines = []
    if peers:
        lines.append(f"Configured peers ({len(peers)}):")
        for name, entry in peers.items():
            auth = (entry.get("auth") or {}).get("type", "none")
            lines.append(f"  - {name}: {entry.get('url', '?')} (auth: {auth})")
    else:
        lines.append("No peers configured. Add them under 'a2a_agents' in config.yaml.")

    convos = protocol.list_conversations()
    if convos:
        lines.append("")
        lines.append(f"Persisted conversations ({len(convos)}):")
        for c in convos[:25]:
            lines.append(f"  - {c}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Tool schemas + registration
# --------------------------------------------------------------------------

_SCHEMAS = {
    "a2a_discover": {
        "type": "function",
        "function": {
            "name": "a2a_discover",
            "description": (
                "Fetch and summarize another agent's A2A Agent Card from a URL "
                "(its name, description, capabilities, and skills). Use this to "
                "find out what a remote agent can do before calling it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Base URL of the remote A2A agent, e.g. http://localhost:9999"},
                },
                "required": ["url"],
            },
        },
    },
    "a2a_call": {
        "type": "function",
        "function": {
            "name": "a2a_call",
            "description": (
                "Send a natural-language task to a remote A2A agent and return "
                "its reply. The agent is a peer (any A2A-compliant framework), "
                "not a sub-agent you control. Pass 'context_id' from a previous "
                "reply to continue a multi-turn exchange."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "agent": {"type": "string", "description": "Configured peer name (from a2a_agents) or a full http(s):// URL."},
                    "message": {"type": "string", "description": "The task / message to send the peer, in natural language."},
                    "context_id": {"type": "string", "description": "Optional: context id from a prior reply, to continue the conversation."},
                    "on_behalf_of": {"type": "string", "description": "User identity represented by this delegation; normally configured on the peer."},
                    "capability": {"type": "string", "description": "Requested capability grant; normally configured on the peer."},
                },
                "required": ["agent", "message"],
            },
        },
    },
    "a2a_list": {
        "type": "function",
        "function": {
            "name": "a2a_list",
            "description": "List configured A2A peer agents and persisted A2A conversations.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
}

_HANDLERS = {
    "a2a_discover": a2a_discover,
    "a2a_call": a2a_call,
    "a2a_list": a2a_list,
}


def register_tools(ctx) -> None:
    """Register the three client tools in the ``a2a`` toolset."""
    for name, schema in _SCHEMAS.items():
        ctx.register_tool(
            name=name,
            toolset="a2a",
            schema=schema,
            handler=_HANDLERS[name],
            description=schema["function"]["description"],
            emoji="\U0001f9e9",  # puzzle piece
        )
