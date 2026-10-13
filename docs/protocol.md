# Internal protocol v1

Relay/agent messages are UTF-8 JSON objects sent as individual WebSocket text frames. The frame limit is 4 MiB. Every message has `version: 1` and a `type`. Unknown JSON fields, unsupported versions, malformed envelopes and oversized frames are rejected.

## Enrollment and connection

1. An operator generates one Ed25519 keypair on the device. The private key stays in a local file; only its base64 public key is copied to relay registration config.
2. The agent initiates `/agent/ws` and sends `hello` with its explicit `device_id`.
3. The relay looks up the registered, non-revoked public key and returns a random 32-byte `challenge`.
4. The agent signs the domain-separated bytes `ato-relay-device-v1\0 || device_id || \0 || challenge` and returns a `proof`.
5. The relay verifies Ed25519 before replacing any existing connection and sends `welcome`.

The challenge expires after 30 seconds. WebSocket heartbeat frames run every 25 seconds; missed pongs make the connection stale. Agent reconnect uses bounded exponential backoff with jitter. A relay restart closes the socket and the agent reconnects.

## Request and response

```json
{"version":1,"type":"request","request_id":"random-128-bit-hex","device_id":"windows-main","method":"system.info","arguments":{}}
{"version":1,"type":"response","request_id":"random-128-bit-hex","device_id":"windows-main","ok":true,"result":{"os":"windows"}}
{"version":1,"type":"response","request_id":"random-128-bit-hex","device_id":"windows-main","ok":false,"error":{"code":"execution_error","message":"policy denied"}}
```

Responses are looked up by request ID in the original device connection. Responses from another device, duplicate responses, and unknown IDs are ignored. A failed response must have a structured error. Requests are independent; no ordering is assumed. The relay bounds in-flight calls and agent worker count.

If an MCP request is canceled, the relay sends a `cancel` message with the same request ID. The agent cancels request-scoped work; long-running sessions created by `process.start` are independent and are explicitly polled or terminated through their session ID. Session output is bounded and read by byte offsets.

The transport and MCP layer are separate. The internal `version` can evolve without inheriting JSON-RPC or HTTP session semantics.
