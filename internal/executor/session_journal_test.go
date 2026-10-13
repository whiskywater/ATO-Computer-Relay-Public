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

func TestJournalNonzeroAndDurableOutput(t *testing.T) {
	x := testExecutor(t)
	defer x.Close()
	x.Policy.SessionJournalDir = filepath.Join(x.Policy.AllowedRoots[0], "journal")
	x.Policy.MaxSessionJournalBytes = 1024
	x.Policy.AllowedTools = append(x.Policy.AllowedTools, "process.sessions")
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "Write-Output 'journal-payload'; Write-Output ('X'*4096); exit 7", "close_stdin": true}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "echo journal-payload; head -c 4096 /dev/zero | tr '\\0' X; exit 7"}, "close_stdin": true}
	}
	started, e := x.Handle(context.Background(), "process.start", args(a))
	if e != nil {
		t.Fatal(e)
	}
	m := started.(map[string]any)
	id := m["session_id"].(string)
	if m["timeout_seconds"].(int64) < 14 || m["timeout_seconds"].(int64) > 16 {
		t.Fatalf("unexpected deadline: %#v", m)
	}
	statusPath := m["journal_status_path"].(string)
	outputPath := m["journal_output_path"].(string)
	if statusPath == "" || outputPath == "" {
		t.Fatal("journal paths missing")
	}
	res, e := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "wait_seconds": 8}))
	if e != nil {
		t.Fatal(e)
	}
	state := res.(map[string]any)
	if state["exit_code"].(*int) == nil || *state["exit_code"].(*int) != 7 || state["exit_reason"] != "exited_nonzero" {
		t.Fatalf("unexpected result: %#v", state)
	}
	var final journalStatus
	b, e := os.ReadFile(statusPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &final); e != nil {
		t.Fatal(e)
	}
	if final.ExitReason != "exited_nonzero" || final.ExitCode == nil || *final.ExitCode != 7 || final.State != "finished" || !final.OutputTruncated || final.OutputBytes != 1024 {
		t.Fatalf("bad journal: %+v", final)
	}
	b, e = os.ReadFile(outputPath)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 1024 || !strings.Contains(string(b), "journal-payload") {
		t.Fatalf("wrong output: %d", len(b))
	}
	if strings.Contains(string(b), "SENSITIVE_COMMAND") {
		t.Fatal("journal exposed unrelated data")
	}
	listed, _ := x.Handle(context.Background(), "process.sessions", args(map[string]any{}))
	if !strings.Contains(stringify(listed), "exited_nonzero") {
		t.Fatalf("list missing reason: %#v", listed)
	}
}

func TestJournalDeadlineAndTimeoutReason(t *testing.T) {
	x := testExecutor(t)
	defer x.Close()
	x.Policy.SessionJournalDir = filepath.Join(x.Policy.AllowedRoots[0], "journal")
	x.Policy.MaxSessionRuntime = 5 * time.Second
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "Write-Output waiting; Start-Sleep -Seconds 8", "close_stdin": true, "timeout_seconds": 1}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "echo waiting; exec sleep 8"}, "close_stdin": true, "timeout_seconds": 1}
	}
	r, e := x.Handle(context.Background(), "process.start", args(a))
	if e != nil {
		t.Fatal(e)
	}
	m := r.(map[string]any)
	if m["timeout_seconds"].(int64) != 1 {
		t.Fatalf("expected 1s deadline got %#v", m)
	}
	id := m["session_id"].(string)
	got, e := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "wait_seconds": 7}))
	if e != nil {
		t.Fatal(e)
	}
	v := got.(map[string]any)
	if v["running"].(bool) || v["exit_reason"] != "deadline_exceeded" {
		t.Fatalf("timeout not classified: %#v", v)
	}
	var final journalStatus
	b, e := os.ReadFile(m["journal_status_path"].(string))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &final); e != nil {
		t.Fatal(e)
	}
	if final.ExitReason != "deadline_exceeded" || final.Finished == nil {
		t.Fatalf("bad deadline status %+v", final)
	}
}

func stringify(v any) string { b, _ := json.Marshal(v); return string(b) }
