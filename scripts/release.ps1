$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$go = (Get-Command go -ErrorAction Stop).Source
$out = Join-Path $repo 'bin'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$commit = 'unknown'
try { $commit = (& git -C $repo rev-parse --short HEAD 2>$null).Trim() } catch { }
if (-not $commit) { $commit = 'unknown' }
$agentFlags = "-s -w -X github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent.Version=0.1.0 -X github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent.Commit=$commit"
$relayFlags = "-s -w -X main.version=0.1.0 -X main.commit=$commit"
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
& $go build -trimpath -ldflags $agentFlags -o (Join-Path $out 'agent-windows-amd64.exe') (Join-Path $repo 'cmd\agent')
if ($LASTEXITCODE -ne 0) { throw 'Windows agent build failed' }
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
& $go build -trimpath -ldflags $relayFlags -o (Join-Path $out 'relay-linux-amd64') (Join-Path $repo 'cmd\relay')
if ($LASTEXITCODE -ne 0) { throw 'Linux relay build failed' }
$env:GOARCH = 'arm64'
& $go build -trimpath -ldflags $relayFlags -o (Join-Path $out 'relay-linux-arm64') (Join-Path $repo 'cmd\relay')
if ($LASTEXITCODE -ne 0) { throw 'Linux arm64 relay build failed' }
Write-Output "Release binaries created in $out"
