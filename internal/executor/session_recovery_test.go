package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Restarted agents can retrieve completed journal evidence, but must never
// incorrectly advertise stale PIDs as live managed sessions.
func TestRecoverArchivedJournalAfterRestart(t *testing.T) {
	x := testExecutor(t)
	dir := filepath.Join(x.Policy.AllowedRoots[0], "journals")
	x.Policy.SessionJournalDir = dir
	x.Policy.MaxSessionJournalBytes = 1 << 20
	a := map[string]any{}
	if runtime.GOOS == "windows" {
		a["shell"] = "powershell"
		a["command"] = "Write-Output 'archived-marker'; exit 0"
	} else {
		a["command"] = "sh"
		a["args"] = []string{"-c", "printf 'archived-marker\n'; exit 0"}
	}
	got, err := x.Handle(context.Background(), "process.start", args(a))
	if err != nil {
		t.Fatal(err)
	}
	id := got.(map[string]any)["session_id"].(string)
	s := x.get(id)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("process did not finish")
	}
	// Recreate executor to emulate service restart.
	restarted := New(x.Policy, "test")
	sessions := restarted.listSessions()["sessions"]
	if sessions == nil {
		t.Fatal("missing recovered session")
	}
	_ = sessions
	read, err := restarted.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id}))
	if err != nil {
		t.Fatal(err)
	}
	gotRead := read.(map[string]any)
	if gotRead["running"] != false || gotRead["archived"] != true || !strings.Contains(gotRead["output"].(string), "archived-marker") {
		t.Fatalf("bad archived status: %#v", gotRead)
	}
	if gotRead["exit_reason"] != "exited_zero" {
		t.Fatalf("reason: %#v", gotRead)
	}
	_, err = restarted.Handle(context.Background(), "process.read", args(map[string]any{"session_id": "../fake"}))
	if err == nil {
		t.Fatal("path traversal session ID accepted")
	}
}

func TestArchiveUnknownRunningState(t *testing.T) {
	x := testExecutor(t)
	dir := filepath.Join(x.Policy.AllowedRoots[0], "journals")
	x.Policy.SessionJournalDir = dir
	id := strings.Repeat("a", 32)
	if err := os.MkdirAll(filepath.Join(dir, id), 0700); err != nil {
		t.Fatal(err)
	}
	data := []byte("{\"session_id\":\"" + id + "\",\"pid\":1234,\"created\":\"2026-10-10T00:00:00Z\",\"state\":\"running\"}")
	if err := os.WriteFile(filepath.Join(dir, id, "status.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id, "output.log"), []byte("partial evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	read, err := x.readArchivedSession(id, 0)
	if err != nil {
		t.Fatal(err)
	}
	state := read.(map[string]any)
	if state["running"] != false || state["exit_reason"] != "unknown_after_agent_restart" || state["state_uncertain"] != true {
		t.Fatalf("old status falsely live: %#v", state)
	}
}
