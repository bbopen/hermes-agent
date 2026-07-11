"""Per-request A2A capability policy enforced by ``pre_tool_call``.

The gateway preserves its session ContextVars into the worker thread that runs
the agent.  That lets the hook below associate every tool call with the A2A
``contextId`` without process-global environment variables or core changes.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import FrozenSet, Optional


@dataclass(frozen=True)
class ActivePolicy:
    principal: str
    on_behalf_of: str
    capability: str
    allowed_tools: FrozenSet[str]


_lock = threading.Lock()
_active: dict[str, ActivePolicy] = {}


def activate(context_id: str, policy: ActivePolicy) -> bool:
    """Install *policy* unless the context already has an in-flight request."""
    with _lock:
        if context_id in _active:
            return False
        _active[context_id] = policy
        return True


def deactivate(context_id: str) -> None:
    with _lock:
        _active.pop(context_id, None)


def get(context_id: str) -> Optional[ActivePolicy]:
    with _lock:
        return _active.get(context_id)


def enforce_tool_scope(tool_name: str = "", **_: object):
    """Block tools outside the active A2A request's capability grant.

    A missing policy for an A2A session fails closed.  ``*`` is retained only
    for localhost/legacy compatibility; production peer policies should always
    enumerate exact tool names through ``capability_tools``.
    """
    try:
        from gateway.session_context import get_session_env

        if get_session_env("HERMES_SESSION_PLATFORM", "") != "a2a":
            return None
        context_id = get_session_env("HERMES_SESSION_CHAT_ID", "")
    except Exception:
        return {
            "action": "block",
            "message": "A2A tool denied: session identity is unavailable",
        }

    policy = get(context_id)
    if policy is None:
        return {
            "action": "block",
            "message": "A2A tool denied: no active capability policy",
        }
    if "*" in policy.allowed_tools or tool_name in policy.allowed_tools:
        return None
    return {
        "action": "block",
        "message": (
            f"A2A tool '{tool_name}' denied: capability "
            f"'{policy.capability}' does not grant it"
        ),
    }
