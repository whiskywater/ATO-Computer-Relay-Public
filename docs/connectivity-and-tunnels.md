# Connectivity, tunnels, and trust boundaries

This is a **generic deployment pattern** for ATO Computer Relay, not an operator's production configuration. All hostnames, addresses, ports, and identifiers in examples are illustrative. Do not publish private endpoints, device inventories, keys, tokens, or recovery runbooks.

## Network path

```text
        ChatGPT or another remote MCP client
                        |
                HTTPS + MCP bearer
                        |
             Public HTTPS hostname
                        |
                 Cloudflare edge
                        |
             Cloudflare Tunnel
                        |
          cloudflared (outbound connector)
                        |
             Local reverse proxy
                        |
                Go relay service
                 /           \
           /mcp              /agent/ws
                                ^
                                | outbound authenticated WSS
                                |
                        Windows ATO agent
                                |
                    Local policy + OS permissions
                                |
                      Approved computer operations
```

This diagram shows logical traffic flow, not an inbound connection to Windows. The agent **initiates** its authenticated WebSocket connection to the relay, and the MCP client makes separate HTTPS requests. The relay correlates requests and responses over those connections.

- **MCP client:** Calls tools through the relay's Streamable HTTP `/mcp` endpoint. ChatGPT is one possible client.
- **Cloudflare Tunnel:** Exposes a public HTTPS endpoint without opening inbound ports on the tunnel host. The `cloudflared` process establishes an outbound connection to Cloudflare.
- **Reverse proxy (optional, such as Caddy):** Routes `/mcp` and `/agent/ws` to a Go relay bound to loopback, passing authorization headers and WebSocket upgrades as required.
- **Go relay:** Requires an MCP bearer token, checks agent identity, and routes authenticated requests.
- **Windows agent:** Connects outward using `wss://` for non-local relay hosts, proves its registered Ed25519 identity, and executes only operations permitted by the agent policy and Windows account.

## Cloudflare or OpenAI tunnel?

**This pattern uses Cloudflare Tunnel, not OpenAI's Secure MCP Tunnel.** ChatGPT is a remote MCP client; its use does not mean that the connection is carried by an OpenAI tunnel. Other deployment methods can be used instead of Cloudflare, but they require separate configuration.

Cloudflare Quick Tunnels use temporary `trycloudflare.com` hostnames which may change on restart and are better suited to experimentation. A **named Cloudflare Tunnel** with an operator-controlled stable hostname is generally more suitable for persistent connectivity. Neither option removes the need for relay authentication or local Windows permissions.

## Illustrative local routing

The following ports are **examples**, not production settings. Deployments should bind the Go service and reverse-proxy origin to loopback where possible.

```text
Cloudflare HTTPS hostname
    -> cloudflared
    -> http://127.0.0.1:8080  (example reverse proxy)
    -> http://127.0.0.1:9000  (example Go relay)
       /mcp       MCP calls
       /agent/ws  agent WebSocket connection
```

A disposable Quick Tunnel can be tested with an operator-chosen local origin port:

```sh
cloudflared tunnel --url http://127.0.0.1:8080
```

The example assumes a separately configured local reverse proxy and Go relay. It is **not** a complete or production-ready installer. For a stable deployment, configure a named tunnel and DNS via Cloudflare's supported process, and update the agent endpoint and MCP client endpoint together.

## Authentication and security boundaries

1. **HTTPS / WSS:** The client-facing hostname is secured with TLS. Cloudflare terminates the public TLS connection in this pattern; operators must account for that trust boundary. The internal HTTP hop is restricted to loopback rather than exposed on the network.
2. **MCP access:** The relay requires a strong secret bearer credential (commonly set with `ATO_MCP_BEARER_TOKEN`). The tunnel alone does **not** authorize commands or filesystem access.
3. **Agent identity:** Each agent has its own Ed25519 private key; only the matching public key belongs in relay registration. Revoke an agent by disabling its registration and rotating compromised credentials.
4. **Local execution:** The Windows agent applies tool, root, and executable restrictions. It should run under a dedicated unprivileged identity. Path validation is **not** a sandbox for arbitrary shell commands; NTFS permissions remain critical.
5. **Exposure:** Do not open a public inbound port on Windows. Keep the relay's origin listener private. Restrict or protect diagnostic endpoints as needed; monitor for unauthorized connection attempts.

## OPSEC checklist for documentation and contributions

Do **not** commit production `agent.json` or `relay.json`, environment files, keys, tokens, real tunnel hostnames, user-specific filesystem paths, home IP addresses, device identifiers, journal output, firewall rules, scheduled-task recovery instructions, or Defender exclusions. Use placeholders such as `relay.example.net` and `example-device`; review **all Git history and branches** before changing repository visibility. Never paste full process command lines or logs if they might contain credentials.

To troubleshoot a deployment, check the public HTTPS endpoint, `cloudflared` connection state, local reverse-proxy routing, relay authentication, agent identity, and agent-local policy in that order. A tunnel being online does **not** establish that a Windows device is online or that a command is authorized.

See [architecture.md](architecture.md), [protocol.md](protocol.md), and [../SECURITY.md](../SECURITY.md) for further implementation and security context.
