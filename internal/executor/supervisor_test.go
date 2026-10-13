package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSupervisorSurvivesConnectionAgentShutdown(t *testing.T) {
	base := testExecutor(t)
	base.Policy.SupervisorEnabled = true
	base.Policy.AllowedTools = append(base.Policy.AllowedTools, "process.sessions")
	base.Policy.SessionJournalDir = filepath.Join(base.Policy.AllowedRoots[0], "durable-journals")
	base.Policy.MaxSessionRuntime = 12 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunSupervisor(ctx, base.Policy, "test", "supervisor-test") }()
	client := New(base.Policy, "test")
	defer client.Close()
	var ready bool
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(filepath.Join(base.Policy.SessionJournalDir, ".supervisor-token")); err == nil {
			if _, err = client.requestSupervisor(context.Background(), "process.sessions", args(map[string]any{})); err == nil {
				ready = true
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("supervisor exited early: %v", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("supervisor never became ready")
	}
	cmd := map[string]any{"close_stdin": true}
	if runtime.GOOS == "windows" {
		cmd["shell"] = "powershell"
		cmd["command"] = "Start-Sleep -Seconds 2; Write-Output durable-marker"
	} else {
		cmd["command"] = "sh"
		cmd["args"] = []string{"-c", "sleep 2; echo durable-marker"}
	}
	started, err := client.Handle(context.Background(), "process.start", args(cmd))
	if err != nil {
		t.Fatal(err)
	}
	startedMap := started.(map[string]any)
	id, _ := startedMap["session_id"].(string)
	if id == "" {
		t.Fatalf("missing session id: %#v", started)
	}
	// Crucial: closing the connection-facing executor must not cancel the job.
	client.Close()
	var result map[string]any
	for i := 0; i < 75; i++ {
		response, e := client.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id}))
		if e != nil {
			t.Fatal(e)
		}
		result = response.(map[string]any)
		if result["running"] == false {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if result["running"] != false || !strings.Contains(result["output"].(string), "durable-marker") {
		t.Fatalf("job did not survive agent shutdown: %#v", result)
	}
	if code, ok := result["exit_code"].(float64); !ok || code != 0 {
		t.Fatalf("bad exit: %#v", result)
	}
	all, err := client.Handle(context.Background(), "process.sessions", json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if all == nil {
		t.Fatal("no session list")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not shut down")
	}
}
