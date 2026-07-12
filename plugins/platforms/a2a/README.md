# A2A — Agent-to-Agent protocol for Hermes

Talk to other agents, and let other agents talk to you, over the open
[A2A protocol](https://a2a-protocol.org). Works with any A2A-compliant peer
(another Hermes, LangChain, CrewAI, Google ADK, OpenClaw, …). Stdlib only — no
`a2a-sdk` dependency.

## Enable

```bash
hermes gateway setup      # pick A2A, or:
```

```yaml
# ~/.hermes/config.yaml
gateway:
  platforms:
    a2a:
      enabled: true
      extra:
        host: "0.0.0.0"
        port: 9900
        advertised_url: "http://hms-m1:9900/"
        agent_name: "worker"
        request_timeout: 15
        reply_timeout: 120
        trusted_peers:
          primary:
            credentials:
              - key_id: "primary-2026-07"
                token_env: "PRIMARY_TO_WORKER_A2A_TOKEN"
            on_behalf_of: ["brett"]
            capabilities: ["system.proof"]
        capability_tools:
          system.proof: ["terminal"]

# peers you want to call (outbound):
a2a_agents:
  worker:
    url: "http://worker.example:9900"
    auth:
      type: bearer
      key_id: "primary-2026-07"
      key_env: "PRIMARY_TO_WORKER_A2A_TOKEN"
    on_behalf_of: "brett"
    capability: "system.proof"
    timeout: 120
```

Store only the credential value in the active profile's `.env`:

```dotenv
PRIMARY_TO_WORKER_A2A_TOKEN=<secret value>
```

Every remote request must present both `Authorization: Bearer ...` and the
matching `X-A2A-Key-Id`. Host, port, timeouts, names, peer policy, and grants
belong in `config.yaml`, not `.env`.

## Outbound — call other agents

The agent gets three tools:

- `a2a_discover(url)` — what can this agent do?
- `a2a_call(agent, message, context_id?)` — send it a task, get the reply.
- `a2a_list()` — configured peers + saved conversations.

## Inbound — be callable

When the `a2a` platform is enabled, Hermes serves an Agent Card at
`http://<host>:<port>/.well-known/agent.json` and accepts JSON-RPC
`message/send` tasks. Incoming tasks are injected into your **live** agent
session — the same agent that's talking to you, with full memory — and the
reply is returned over A2A.

## Security

- **Local mode is actually loopback-bound.** Without an active `trusted_peers`
  credential, the server binds numeric `127.0.0.1` and verifies the created
  socket. `A2A_BEARER_TOKEN` can authenticate that loopback-only compatibility
  mode but never widens exposure.
- **Remote peers need explicit policy.** Configure named `trusted_peers` keys
  (each with a distinct `key_id` and `token_env`), OBO/capability grants, and
  `capability_tools`. Two active keys are supported during rotation; revoked
  and expired keys stop authenticating on the next request.
- **Wildcard binds need an explicit public origin.** When `host` is `0.0.0.0`
  or `::`, set `advertised_url` to the exact `http(s)` origin peers use (for
  example a tailnet hostname). Userinfo, query strings, fragments, paths, and
  wildcard hosts are rejected; the client still pins RPC calls to that origin.
- Inbound text is run through prompt-injection filters and framed as untrusted
  peer input.
- Outbound text is scrubbed of credential-shaped strings.
- Every exchange is logged under the active profile at `a2a_audit.jsonl`.
- Conversations persist under the active profile's `a2a_conversations/` — they
  survive context compaction and restarts.
- Task/idempotency state and the retryable audit outbox live under the active
  profile's `a2a/control-plane/` directory.

## Env vars

| Var | Default | Meaning |
|---|---|---|
| `A2A_BEARER_TOKEN` | _(unset)_ | Legacy loopback compatibility auth only; it never enables remote delegation. |

All non-secret behavior is configured under
`gateway.platforms.a2a.extra` in `config.yaml`. `A2A_BEARER_TOKEN` is the only
legacy environment setting documented by this plugin; named remote secrets use
the operator-chosen `token_env` / `key_env` names shown above.

See `DESIGN.md` for architecture and the requirement-tracing table.
