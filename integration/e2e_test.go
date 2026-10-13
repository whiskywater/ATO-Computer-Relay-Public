package integration

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/devices"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/executor"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/relay"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/transport"
)

const bearer = "integration-test-token-not-a-real-secret-0123456789"

type serverState struct {
	server   *http.Server
	listener net.Listener
	hub      *transport.Hub
	registry *devices.Registry
	address  string
}

func startRelay(t *testing.T, address string, reg transport.RegisteredDevice) *serverState {
	t.Helper()
	ln, e := net.Listen("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	registry := devices.NewRegistry()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	hub := transport.NewHub([]transport.RegisteredDevice{reg}, registry, logger)
	m := (&relay.MCP{Hub: hub, Devices: registry, Logger: logger}).Server()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, PropagateRequestCancellation: true})
	secured, e := auth.BearerMiddleware(bearer, handler)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	mux.Handle("/agent/ws", hub)
	mux.Handle("/mcp", secured)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	s := &serverState{server: srv, listener: ln, hub: hub, registry: registry, address: ln.Addr().String()}
	go func() { _ = srv.Serve(ln) }()
	return s
}
func (s *serverState) stop() {
	s.hub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
	_ = s.listener.Close()
}

type bearerRoundTripper struct {
	base  http.RoundTripper
	token string
}

func (r bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+r.token)
	return r.base.RoundTrip(clone)
}
func connectMCP(ctx context.Context, address string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "ato-relay-integration-test", Version: "1"}, nil)
	httpClient := &http.Client{Transport: bearerRoundTripper{base: http.DefaultTransport, token: bearer}}
	tr := &mcp.StreamableClientTransport{Endpoint: "http://" + address + "/mcp", HTTPClient: httpClient, DisableStandaloneSSE: true}
	return client.Connect(ctx, tr, nil)
}

func TestAgentRelayMCPAndRelayRestart(t *testing.T) {
	pub, priv, e := auth.GenerateDeviceKey()
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.PublicKey(pub)
	dev := transport.RegisteredDevice{ID: "windows-main", Name: "Windows Main", PublicKey: key}
	state := startRelay(t, "127.0.0.1:0", dev)
	defer func() { state.stop() }()
	root := t.TempDir()
	p := policy.Policy{AllowedRoots: []string{root}, AllowedTools: []string{"system.info", "process.run", "process.start", "process.read", "process.sessions", "process.shell"}, AllowedCommands: []string{"powershell.exe", "sh", "printf"}, MaxCommandRuntime: 15 * time.Second, MaxSessionRuntime: 12 * time.Second, MaxOutputBytes: 1 << 18}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	client := &agent.Client{URL: "ws://" + state.address + "/agent/ws", DeviceID: dev.ID, Name: dev.Name, PrivateKey: priv, Executor: executor.New(p, agent.Version), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ReconnectMax: 500 * time.Millisecond}
	agentDone := make(chan error, 1)
	go func() { agentDone <- client.Run(agentCtx) }()
	waitOnline(t, state.registry)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, e := connectMCP(ctx, state.address)
	if e != nil {
		t.Fatal(e)
	}
	tools, e := session.ListTools(ctx, &mcp.ListToolsParams{})
	if e != nil {
		t.Fatal(e)
	}
	if len(tools.Tools) < 10 {
		t.Fatalf("expected discoverable computer tools, got %d", len(tools.Tools))
	}
	if runtime.GOOS == "windows" {
		callTool(t, ctx, session, "command_run", map[string]any{"device_id": dev.ID, "shell": "powershell", "command": "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); Write-Output 'windows relay proof ✓'"}, "windows relay proof")
	} else {
		callTool(t, ctx, session, "command_run", map[string]any{"device_id": dev.ID, "command": "printf", "args": []string{"MCP relay proof"}}, "MCP relay proof")
	}
	var wg sync.WaitGroup
	for _, label := range []string{"parallel-alpha", "parallel-beta"} {
		wg.Add(1)
		go func(label string) {
			defer wg.Done()
			cmd := map[string]any{"device_id": dev.ID, "shell": "powershell", "command": fmt.Sprintf("Start-Sleep -Milliseconds 200; Write-Output '%s'", label)}
			if runtime.GOOS != "windows" {
				cmd = map[string]any{"device_id": dev.ID, "command": "sh", "args": []string{"-c", fmt.Sprintf("sleep 0.2; printf %s", label)}}
			}
			callTool(t, ctx, session, "command_run", cmd, label)
		}(label)
	}
	wg.Wait()
	var longCmd map[string]any
	if runtime.GOOS == "windows" {
		longCmd = map[string]any{"device_id": dev.ID, "shell": "powershell", "command": "Start-Sleep -Seconds 3; Write-Output 'reconnected-job-finished'", "close_stdin": true}
	} else {
		longCmd = map[string]any{"device_id": dev.ID, "command": "sh", "args": []string{"-c", "sleep 3; printf reconnected-job-finished"}, "close_stdin": true}
	}
	started, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "process_start", Arguments: longCmd})
	if e != nil || started.IsError {
		t.Fatalf("could not start reconnect test job: %v / %#v", e, started)
	}
	var launch struct {
		Result struct {
			SessionID string `json:"session_id"`
		} `json:"result"`
	}
	body, _ := json.Marshal(started.StructuredContent)
	if e = json.Unmarshal(body, &launch); e != nil || launch.Result.SessionID == "" {
		t.Fatalf("missing process session id: %s, %v", body, e)
	}
	processSessionID := launch.Result.SessionID
	session.Close()
	state.stop()
	state = startRelay(t, state.address, dev)
	waitOnline(t, state.registry)
	session, e = connectMCP(ctx, state.address)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if runtime.GOOS == "windows" {
		callTool(t, ctx, session, "command_run", map[string]any{"device_id": dev.ID, "shell": "powershell", "command": "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); Write-Output 'after relay restart'"}, "after relay restart")
	} else {
		callTool(t, ctx, session, "command_run", map[string]any{"device_id": dev.ID, "command": "printf", "args": []string{"after relay restart"}}, "after relay restart")
	}
	callTool(t, ctx, session, "process_sessions", map[string]any{"device_id": dev.ID}, processSessionID)
	callTool(t, ctx, session, "process_read", map[string]any{"device_id": dev.ID, "session_id": processSessionID, "wait_seconds": 8}, "reconnected-job-finished")
	stopAgent()
	select {
	case e := <-agentDone:
		if e != nil {
			t.Fatalf("agent shutdown failed: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not shut down promptly")
	}
}
func waitOnline(t *testing.T, r *devices.Registry) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := r.Get("windows-main"); ok && d.Online {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("agent did not connect")
}
func callTool(t *testing.T, ctx context.Context, s *mcp.ClientSession, name string, args any, contains string) {
	t.Helper()
	result, e := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if e != nil {
		t.Fatal(e)
	}
	if result.IsError {
		b, _ := json.Marshal(result)
		t.Fatalf("tool %s failed: %s", name, b)
	}
	b, _ := json.Marshal(result)
	if !strings.Contains(string(b), contains) {
		t.Fatalf("tool %s result missing %q: %s", name, contains, b)
	}
}
