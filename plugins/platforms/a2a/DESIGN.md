# A2A Platform Plugin — Design

Consolidates the entire A2A (Agent-to-Agent) feature cluster (#514 and friends)
into one **plugin**, built primarily on capabilities the current codebase
already exposes. The gateway has one narrow generic-listener integration: A2A
is classified as a port-binding platform so secondary multiplex profiles fail
fast instead of starting a second profile-owned control plane.

## Why a plugin, not a core feature

Earlier A2A attempts (#4135, #4948, #4952, #11025) added a standalone server
package (`a2a_adapter/`) and/or patched `gateway/run.py` + `gateway/config.py`.
Since then the codebase grew `ctx.register_platform()` (the plugin
platform-adapter API — used by irc, line, teams, ntfy, simplex, …) and
`ctx.register_tool()`. That makes the standing policy achievable: **plugins
must not special-case product behavior in core files.** A2A behavior remains
under `plugins/platforms/a2a/`; the gateway change only applies its existing
secondary-profile listener gate.

## Two directions

### Outbound — client tools (`a2a` toolset)
- `a2a_discover(url)` — fetch + summarize a peer's Agent Card.
- `a2a_call(agent, message, context_id?)` — send a JSON-RPC `message/send`
  task to a peer, return the reply. Multi-turn via `context_id`.
- `a2a_list()` — configured peers + persisted conversations.

Peers resolved from `config.yaml` → `a2a_agents`, or a direct URL.

### Inbound — platform adapter
- Stdlib `http.server` on a daemon thread (no asyncio loop needed at
  `register()` time — sidesteps the a2a_fleet "register outside a loop" bug
  class that killed inbound serving in forks).
- Agent Card at `GET /.well-known/agent.json`.
- JSON-RPC `message/send` at `POST /`.
- **Live-session injection (the #11025 insight):** inbound tasks route through
  the normal `MessageEvent` → `handle_message` path keyed by the A2A
  `contextId`, so the agent that answers is the same one serving the user —
  full memory/context, not a clone. The reply returns through `adapter.send()`,
  which fulfils a per-context `Future` the HTTP request is blocked on
  (async gateway → synchronous request/response for the caller).

## Security (on by default)
- **Bind safety:** without an active named `trusted_peers` credential, bind
  numeric `127.0.0.1` and verify the created socket is loopback. A legacy local
  bearer never widens exposure.
- **Bearer auth:** constant-time (`hmac.compare_digest`) on inbound POST;
  remote identity requires an unambiguous key ID and token pair. Duplicate key
  IDs or bearer values are rejected across the complete active key set.
- **Authorization:** contexts/tasks are bound to principal, OBO, and capability;
  exact tool grants are activated only for that live A2A context.
- **Injection filters:** inbound text is defanged (ChatML / role-prefix /
  override patterns → `[filtered]`) and framed with a privacy prefix marking it
  untrusted peer input.
- **Outbound redaction:** credential-shaped strings (`sk-…`, `ghp_…`, JWTs,
  bearer tokens, emails) plus the exact peer bearer used for the call are
  scrubbed before untrusted peer data reaches output or persistence.
- **Audit log:** profile-scoped append-only `a2a_audit.jsonl`; pending delivery
  is retained in a claimable SQLite outbox and retried without two live
  instances delivering the same claim concurrently.
- **Transport:** outbound DNS validation and the actual TCP connect share the
  same resolved socket address. Redirects and cross-origin Agent Cards are
  rejected before credentials can be forwarded. Credentialed public peers
  require HTTPS; configured private/tailnet peers may use HTTP.

## Persistence (survives compaction)
A2A conversations are written beneath the active profile at
`a2a_conversations/<context>.jsonl`. Principal-bound task state, canonical
request hashes, fenced execution leases, terminal immutability, and the audit
outbox live at `a2a/control-plane/tasks.sqlite3`. A restart never redispatches
an accepted request; an expired dispatched lease becomes explicitly uncertain.

## Requirements traced to the cluster

| Source | Requirement | Where |
|---|---|---|
| #514, #23871, #4135 | Agent Card discovery | `protocol.build_agent_card`, adapter GET |
| #4135, #14559, #8948 | Client: discover / call / list | `tools.py` |
| #11025 | Live-session injection (not a clone) | `adapter._handle_inbound_task` |
| #11025 | Privacy filters + outbound redaction + audit | `security.py` |
| #11025 | Conversation persistence outside compaction | `protocol.persist_message` |
| #514, #11025 | Key-id bearer auth, verified localhost-default | `security.resolve_bind_host`, adapter bind check |
| #25176, #689 | Agent↔agent messaging across machines | client tools + inbound adapter |

## Deliberately out of scope (future, not this PR)
- **a2a-sdk / SSE streaming.** Wire format here is spec-compatible; an optional
  `[a2a]` extra can upgrade the transport later without changing the contract.
- **DID / Ed25519 identity, OAuth2 scopes, x402 micropayments** (#14559 bindu) —
  heavy, niche; revisit if there's real demand.
- **Local multi-agent orchestration / routing** (#7517, #25660, #15422, #12436,
  #4529) — a *different* problem (in-process delegation, per-agent profiles),
  not the A2A network protocol. Left to their own threads.

## Files
```
plugins/platforms/a2a/
├── plugin.yaml      # manifest (kind: platform)
├── __init__.py      # register(): platform adapter + client tools
├── adapter.py       # inbound A2A server (stdlib http.server)
├── tools.py         # outbound client tools
├── protocol.py      # Agent Card, JSON-RPC framing, persistence
├── security.py      # auth, injection filters, redaction, audit
├── DESIGN.md
└── README.md
```
