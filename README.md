# ATO Computer Relay

Public source snapshot of a self-hosted remote computer control relay. A Windows agent opens an authenticated outbound connection to a Go relay. MCP clients connect to the relay over Streamable HTTP. The relay does not open an inbound Windows port and does not depend on Supabase or a third-party realtime service.

> This is a public source snapshot for trusted operators. Shell tools can change the Windows machine. Run the agent under a dedicated, low-privilege Windows account and grant that account access only to the work roots and tools it needs.

## Architecture

```text
ChatGPT-compatible remote MCP client
           | HTTPS / Streamable HTTP
           v
       Go relay (/mcp)
           | authenticated outbound WebSocket (/agent/ws)
           ^
       Windows agent
          / | \
 filesystem process sessions system info
```

See [docs/architecture.md](docs/architecture.md) and [docs/protocol.md](docs/protocol.md) for the trust model and wire contract.

## Security model

* Agents authenticate using per-device Ed25519 keys and a fresh challenge. Private keys stay on their Windows machine; the relay config stores only public keys.
* MCP requests require a bearer token of at least 32 characters, supplied through `ATO_MCP_BEARER_TOKEN`. Tokens and private keys are not logged.
* The Windows agent enforces allowed roots, denied path subtrees, allowed tools, an executable allowlist, denied command substrings, maximum runtime and output size. Path checks do not sandbox arbitrary commands.
* Shell commands execute as the Windows account running the service. Windows NTFS permissions for a restricted service account are the OS security boundary. Denied command substrings are not a shell sandbox.
* Audit logs contain request ID, client identity label, device ID, method, success/failure and duration. File contents, environment overrides, bearer tokens and private keys are omitted.
* Transport authentication and protocol messages are bounded. The relay bounds pending requests, per-device work, agent workers and process sessions.

## Repository layout

* `cmd/relay`, `cmd/agent` — service entry points
* `internal/relay`, `internal/transport`, `internal/protocol` — MCP surface and relay/agent contract
* `internal/agent`, `internal/executor`, `internal/policy` — outbound agent and local execution boundary
* `internal/auth`, `internal/config`, `internal/devices` — key proof, configuration and live device state
* `integration` — Streamable HTTP, agent routing, concurrency and relay restart test
* `config`, `deploy`, `scripts`, `docs` — example config, service units, release scripts and design documents

## Requirements and build

Go 1.27 or newer is used for this build. The project targets Windows amd64 agents and Linux amd64 relays (Linux arm64 is also supported).

```powershell
go test ./...
go vet ./...
go test -race ./...
go build -o bin/agent.exe ./cmd/agent
```

The race detector requires a supported C compiler runtime; run it on the G3/Linux host if unavailable on Windows. Build release artifacts with `scripts/release.ps1` or `scripts/release.sh`.

## Enroll a Windows agent

1. On the Windows device, generate a private key:

   ```powershell
   .\agent.exe -keygen -key-out C:\ATO\secrets\example-device.key
   ```

   The command prints the public key and private key file path. Keep the private key file readable only by the service account.

2. Copy only the public key into the relay `devices` array in `config/relay.json`, using a stable device ID such as `example-device`. Set the display name. The relay rejects unregistered IDs.

3. Copy `config/agent.example.json` to a private local config file. Set `relay_url` to `wss://<your-host>/agent/ws`, point `private_key_file` at the generated key, and set `allowed_roots` to the ATO working directories needed on this computer. Review every allowed tool and command. The public example allows read-only tools only; opt in to process and shell tools with a narrow absolute-path executable allowlist.

4. Start the relay first, then the Windows agent:

   ```powershell
   .\agent.exe -config C:\ATO\agent.json
   ```

The agent reconnects after relay restarts and uses jittered exponential backoff. Heartbeats detect stale sockets. `log_file` selects a JSON-lines agent log; otherwise logs go to stderr.

### Windows unattended startup

The binary implements the Windows Service Control Manager lifecycle. For unattended startup, run it as a dedicated local service account (for example, `NT AUTHORITY\LocalService`) and grant that identity read access to the binary/config/private key and modify access only to its configured work roots. Do not run the agent as LocalSystem or an administrator for routine use.

From an elevated PowerShell used by an administrator, an example service registration is:

```powershell
sc.exe create ATOComputerAgent binPath= '"C:\ATO\agent.exe" -config "C:\ATO\agent.json"' start= auto obj= 'NT AUTHORITY\LocalService'
sc.exe start ATOComputerAgent
```

To stop and remove it:

```powershell
sc.exe stop ATOComputerAgent
sc.exe delete ATOComputerAgent
```

Create the log directory and grant the service account write permission if `log_file` is configured. Alternatively run the console agent under a non-admin user and use that user's Scheduled Task at logon.

## Configure the relay

Copy `config/relay.example.json` to a private `relay.json`. Replace the demonstration device public key. The example listens on loopback so it is suitable for a same-host reverse proxy or local testing.

Set a long random token in the service environment; do not put it in source control:

```powershell
$env:ATO_MCP_BEARER_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLowerInvariant()
```

Linux example:

```sh
export ATO_MCP_BEARER_TOKEN="$(openssl rand -hex 32)"
./relay -config /etc/ato-computer-relay/relay.json
```

`ATO_RELAY_LISTEN` overrides `listen_address`; `ATO_PUBLIC_URL` overrides `public_url`; the token is read from `ATO_MCP_BEARER_TOKEN`. The relay refuses to start without a token and at least one device registration.

Revocation: set the affected entry's `revoked` field to `true` (or remove its key), then restart the relay. The relay will reject new sockets for that device. Rotate keys and enroll again before reconnecting. Registration and revocation config must be protected from untrusted writers.

## Tool surface

The relay exposes typed MCP tools for device list/status; system information; filesystem list/read/write/mkdir/move/stat; command run; process start/read/stdin/terminate; and process list/kill. Every routed operation requires an explicit `device_id`.

Filesystem roots and denied subtrees are enforced locally by the agent. Command execution runs in the agent's OS identity, with an optional allowed executable list and local command deny patterns. Process output is bounded; long-running sessions return a session ID and support offset-based reads, stdin and termination. `process.kill` refuses the agent itself, reserved low PIDs and protected process names, and applies configured denied process names.

## Run and deploy the Linux relay

Build it without Docker:

```sh
go build -trimpath -o bin/relay ./cmd/relay
```

The included [systemd unit](deploy/ato-computer-relay.service) runs as an unprivileged `ato-relay` user and reads a root-owned environment file. Install the unit and config, set the bearer token in `relay.env`, and start it with systemd. Graceful SIGTERM closes agent WebSockets and allows HTTP handlers to drain.

For public deployment, point a DNS hostname to the relay host and use a reverse proxy with HTTPS/WSS. [deploy/Caddyfile.example](deploy/Caddyfile.example) is a starting point; nginx works with WebSocket upgrade forwarding as well. Keep the Go process bound to loopback behind the proxy. Alternatively set `ATO_RELAY_TLS_CERT` and `ATO_RELAY_TLS_KEY` for native TLS. Do not expose the Windows agent endpoint.

Health endpoints: `/healthz` reports process/version/protocol; `/readyz` reports registered and online device counts. They are diagnostics, not evidence that a device is online.

## MCP transport and ChatGPT Web

The MCP layer uses the official `github.com/modelcontextprotocol/go-sdk` `v1.7.0` and stateless Streamable HTTP. SDK `v1.7.0` supports the current 2026-07-28 MCP specification and older protocol revisions; stateless mode is required by that current revision. This keeps MCP transport separate from the internal agent protocol and avoids relay session affinity. The integration test uses the same Go SDK client over HTTP to discover tools and call them.

The tested endpoint is `/mcp`. It requires `Authorization: Bearer <token>`. An HTTPS hostname and a secure bearer/OAuth credential are required before remote use. This repository does not implement an OAuth authorization server or refresh-token flow: the static bearer boundary is suitable for MCP clients that can send a bearer header, but ChatGPT Web custom app registration may require an OAuth identity provider. Do not switch this remote control endpoint to unauthenticated access.

Current ChatGPT Web custom MCP apps require an eligible workspace plan and Developer mode permission. Full write-capable MCP apps are currently documented for Business and Enterprise/Edu. After deployment and auth are configured, an authorized user creates a custom app with the MCP endpoint, selects the supported authentication mode, scans the tools, and tests before publishing. If the relay is only reachable on a private network, OpenAI documents Secure MCP Tunnel as an alternative to exposing it directly. No ChatGPT app was registered from this run because there is no deployed HTTPS endpoint or OAuth provider to configure.

## Tests and integration

```powershell
go test ./...
go test -race ./...
go vet ./...
```

`integration/TestAgentRelayMCPAndRelayRestart` starts an authenticated relay and agent client, discovers MCP tools, exercises Windows command output through the correlation path, checks concurrent calls, restarts the relay and confirms reconnection. Transport tests use fake agents to cover proof of possession, out-of-order/unknown responses, isolation and connection replacement. Executor tests cover paths with spaces, UTF-8, stdout/stderr, nonzero exit, environment overrides, working directory, timeout, session output and termination.

## Troubleshooting

* Relay exits at startup: verify `ATO_MCP_BEARER_TOKEN` is present and at least 32 characters, JSON is valid, and every non-revoked device key decodes to 32 bytes.
* Agent cannot connect: check `/healthz`, DNS, outbound TLS trust, `relay_url`, firewall egress and whether the device ID/key pair matches relay config.
* Device is offline: inspect relay and agent JSON logs. A reconnect replaces only the same device ID.
* Tool call reports denied path/tool/command: adjust the agent's local policy and restart the agent; the relay cannot override it.
* MCP client cannot discover tools: verify endpoint ends in `/mcp`, HTTPS is valid, Authorization is present and the client supports Streamable HTTP.
* Windows service log is empty: verify the service identity can create/append to `log_file` and read the config/key. If no log file is set, run the binary in a console to inspect stderr.

## Limitations and next hardening

The live registry, registrations and request routing state are in memory/static config. Multiple relay replicas need shared device ownership and revocation state. OAuth/OIDC issuance and refresh are not included. Audit logs are structured but not tamper-evident or stored in a separate append-only database. Filesystem checks are application checks and have normal time-of-check/time-of-use exposure; NTFS ACLs and an unprivileged service account remain essential. A shell-capable compromised relay can run commands allowed to the service account. GUI input, screenshots, clipboard and desktop-session interaction are not part of this MVP. The relay has no public hostname or production TLS deployment in this repository state.

This public source snapshot contains no private production configuration or historical operational commits. Do not assume the source has completed an independent security certification.

## License and ownership

Copyright (c) 2026 whiskywater. Released under the permissive MIT License. Contributors and downstream users must retain the copyright notice and license in copies or substantial portions; the original copyright remains with its holder. See [LICENSE](LICENSE).
