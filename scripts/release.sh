#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/bin"
commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || printf unknown)
agent_flags="-s -w -X github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent.Version=0.1.0 -X github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent.Commit=$commit"
relay_flags="-s -w -X main.version=0.1.0 -X main.commit=$commit"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$agent_flags" -o "$root/bin/agent-windows-amd64.exe" "$root/cmd/agent"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$relay_flags" -o "$root/bin/relay-linux-amd64" "$root/cmd/relay"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$relay_flags" -o "$root/bin/relay-linux-arm64" "$root/cmd/relay"
