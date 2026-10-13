# Architecture

```text
ChatGPT-compatible remote MCP client
           | HTTPS, Streamable HTTP, bearer boundary
           v
   Go relay (/mcp)  ---- in-memory device registry + bounded pending calls
           | outbound-agent WebSocket endpoint (/agent/ws)
           ^ TLS/WSS
           |
   Windows agent (per-device Ed25519 key)
       |-- filesystem tools (agent-local path policy)
       |-- process and shell tools (agent-local command policy)
       |-- process sessions and system information
```

The relay's HTTP/MCP layer maps validated tool calls into `internal/protocol` requests. The agent connection is authenticated independently and persists outbound from Windows. The agent dispatches requests to its platform-neutral executor; `os/exec` uses Windows-native command resolution and `taskkill /T` process-tree termination on Windows. MCP transport code contains no Windows execution logic.

The relay is a single process with a concurrency-safe in-memory registry. Configuration supplies registered public keys and revocation state. There is no database dependency. Requests carry random 128-bit IDs; each device has an isolated pending map and a queue cap, with a relay-wide pending cap. Deadlines and cancellation propagate to the agent. An authenticated reconnect replaces only that device's prior socket.

To scale to multiple relay replicas, introduce a shared device lease/connection directory, a durable request broker or per-device ownership routing, shared registration/revocation storage, and an idempotent handoff protocol. MCP HTTP is stateless so the external tool interface does not need session affinity. Do not put private agent keys in shared relay storage.

## Trust boundaries

* MCP bearer authentication is checked on every request. Tokens and key material are never logged.
* Each agent proves possession of its own Ed25519 private key against a fresh, expiring challenge. TLS/WSS protects public deployments; local tests can use loopback HTTP/WebSocket.
* Filesystem tools canonicalize existing paths and enforce allowed roots and denied subtrees. These checks are a useful application boundary, but cannot contain an arbitrary shell command.
* Commands execute as the Windows account running the agent. For a strong OS boundary, run the Windows service as a dedicated low-privilege account and grant that account NTFS access only to configured work roots and required build tools. Do not use an administrator account for unattended operation.
* Denied command substrings are defense in depth, not a shell sandbox. A compromised relay with shell permission can execute commands available to the service account.
* Tool arguments and file contents are not written to audit logs. Audit records include request ID, client boundary label, device, method, result and duration.
