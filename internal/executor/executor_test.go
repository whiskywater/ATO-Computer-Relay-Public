package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
)

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	root := filepath.Join(t.TempDir(), "workspace with spaces")
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	p := policy.Policy{AllowedRoots: []string{root}, AllowedTools: []string{"fs.list", "fs.read", "fs.search", "fs.replace", "fs.write", "fs.mkdir", "fs.move", "fs.stat", "process.run", "process.start", "process.read", "process.stdin", "process.terminate", "process.list", "process.kill", "process.shell"}, AllowedCommands: []string{"powershell.exe", "sh"}, MaxCommandRuntime: 15 * time.Second, MaxOutputBytes: 32 << 10}
	return New(p, "test")
}
func args(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestFilesystemToolsAndPathPolicy(t *testing.T) {
	x := testExecutor(t)
	root := x.Policy.AllowedRoots[0]
	file := filepath.Join(root, "with space.txt")
	if _, e := x.Handle(context.Background(), "fs.write", args(map[string]any{"path": file, "content": "héllø UTF-8"})); e != nil {
		t.Fatal(e)
	}
	got, e := x.Handle(context.Background(), "fs.read", args(map[string]any{"path": file}))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(got.(map[string]any)["content"].(string), "héllø") {
		t.Fatalf("unexpected read result: %#v", got)
	}
	if _, e = x.Handle(context.Background(), "fs.stat", args(map[string]any{"path": file})); e != nil {
		t.Fatal(e)
	}
	renamed := filepath.Join(root, "renamed.txt")
	if _, e = x.Handle(context.Background(), "fs.move", args(map[string]any{"from": file, "to": renamed})); e != nil {
		t.Fatal(e)
	}
	if _, e = x.Handle(context.Background(), "fs.list", args(map[string]any{"path": root})); e != nil {
		t.Fatal(e)
	}
	if _, e = x.Handle(context.Background(), "fs.read", args(map[string]any{"path": filepath.Join(root, "..", "outside.txt")})); e == nil {
		t.Fatal("read outside allowed root succeeded")
	}
}

func TestProcessStreamsExitCodeEnvironmentAndWorkingDirectory(t *testing.T) {
	x := testExecutor(t)
	root := x.Policy.AllowedRoots[0]
	a := map[string]any{"working_directory": root, "environment": map[string]string{"ATO_TEST_VALUE": "from override"}}
	if runtime.GOOS == "windows" {
		a["shell"] = "powershell"
		a["command"] = `[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); Write-Output $env:ATO_TEST_VALUE; Write-Output (Get-Location).Path; [Console]::Error.WriteLine('stderr ✓'); exit 7`
	} else {
		a["command"] = "sh"
		a["args"] = []string{"-c", "printf '%s\\n%s' \"$ATO_TEST_VALUE\" \"$PWD\"; printf 'stderr ✓' >&2; exit 7"}
	}
	got, e := x.Handle(context.Background(), "process.run", args(a))
	if e != nil {
		t.Fatal(e)
	}
	v := got.(map[string]any)
	if v["exit_code"].(int) != 7 {
		t.Fatalf("unexpected exit code %#v", v)
	}
	if !strings.Contains(v["stdout"].(string), root) || !strings.Contains(v["stdout"].(string), "from override") {
		t.Fatalf("working directory/env mismatch: %#v", v)
	}
	if !strings.Contains(v["stderr"].(string), "stderr") {
		t.Fatalf("stderr missing: %#v", v)
	}
	if runtime.GOOS == "windows" && !strings.Contains(v["stderr"].(string), "✓") {
		t.Fatalf("UTF-8 stderr missing: %#v", v)
	}
}

func TestCommandTimeoutAndLongRunningSession(t *testing.T) {
	x := testExecutor(t)
	var timeout map[string]any
	if runtime.GOOS == "windows" {
		timeout = map[string]any{"shell": "powershell", "command": "Start-Sleep -Seconds 30", "timeout_seconds": 1}
	} else {
		timeout = map[string]any{"command": "sh", "args": []string{"-c", "sleep 30"}, "timeout_seconds": 1}
	}
	start := time.Now()
	if _, e := x.Handle(context.Background(), "process.run", args(timeout)); e == nil || !strings.Contains(e.Error(), "timed out") {
		t.Fatalf("timeout error expected, got %v", e)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
	var startArgs map[string]any
	if runtime.GOOS == "windows" {
		startArgs = map[string]any{"shell": "powershell", "command": "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); Write-Output 'session-ready'; Start-Sleep -Seconds 30"}
	} else {
		startArgs = map[string]any{"command": "sh", "args": []string{"-c", "echo session-ready; sleep 30"}}
	}
	res, e := x.Handle(context.Background(), "process.start", args(startArgs))
	if e != nil {
		t.Fatal(e)
	}
	id := res.(map[string]any)["session_id"].(string)
	// PowerShell startup latency can exceed 150 ms on Windows build hosts.
	// Poll for readiness rather than failing a healthy supervised process.
	var read any
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		read, e = x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id}))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(read.(map[string]any)["output"].(string), "session-ready") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(read.(map[string]any)["output"].(string), "session-ready") {
		t.Fatalf("session output missing: %#v", read)
	}
	state := read.(map[string]any)
	offset := state["next_offset"].(int)
	next, e := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "offset": offset}))
	if e != nil {
		t.Fatal(e)
	}
	if next.(map[string]any)["output"].(string) != "" {
		t.Fatalf("offset read repeated old output: %#v", next)
	}
	if _, e = x.Handle(context.Background(), "process.terminate", args(map[string]any{"session_id": id})); e != nil {
		t.Fatal(e)
	}
}

func TestProcessListingAndProtectedKill(t *testing.T) {
	x := testExecutor(t)
	listed, e := x.Handle(context.Background(), "process.list", args(map[string]any{}))
	if e != nil {
		t.Fatal(e)
	}
	if len(listed.(map[string]any)["processes"].([]ProcessInfo)) == 0 {
		t.Fatal("process list is empty")
	}
	if _, e = x.Handle(context.Background(), "process.kill", args(map[string]any{"pid": os.Getpid()})); e == nil || !strings.Contains(e.Error(), "protected") {
		t.Fatalf("expected protected process denial, got %v", e)
	}
}

func TestOutputIsBounded(t *testing.T) {
	x := testExecutor(t)
	x.Policy.MaxOutputBytes = 1024
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "'x' * 100000"}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "head -c 100000 /dev/zero"}}
	}
	got, e := x.Handle(context.Background(), "process.run", args(a))
	if e != nil {
		t.Fatal(e)
	}
	if len(got.(map[string]any)["stdout"].(string)) > 1024 {
		t.Fatal("output exceeded configured cap")
	}
}

func TestExecutorShutdownReapsSessions(t *testing.T) {
	x := testExecutor(t)
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "Start-Sleep -Seconds 30"}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "sleep 30"}}
	}
	started, e := x.Handle(context.Background(), "process.start", args(a))
	if e != nil {
		t.Fatal(e)
	}
	id := started.(map[string]any)["session_id"].(string)
	x.Close()
	got, e := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id}))
	if e != nil {
		t.Fatal(e)
	}
	if got.(map[string]any)["running"].(bool) {
		t.Fatal("child process remained running after executor shutdown")
	}
}

func startQuickExit(t *testing.T, x *Executor, content string) string {
	t.Helper()
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "Write-Output '" + content + "'"}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "printf '%s' '" + content + "'"}}
	}
	v, err := x.Handle(context.Background(), "process.start", args(a))
	if err != nil {
		t.Fatal(err)
	}
	id := v.(map[string]any)["session_id"].(string)
	// A quick command can still take more than two seconds to initialize PowerShell.
	// Verify it actually exited before using it as an eviction candidate.
	deadline := time.Now().Add(8 * time.Second)
	for {
		result, e := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "wait_seconds": 1}))
		if e != nil {
			t.Fatal(e)
		}
		if result.(map[string]any)["running"] == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("quick-exit child did not finish")
		}
	}
	return id
}

func TestCompletedSessionSurvivesSubsequentStart(t *testing.T) {
	x := testExecutor(t)
	id := startQuickExit(t, x, "retained-output")
	_ = startQuickExit(t, x, "later-output")
	got, err := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id}))
	if err != nil || !strings.Contains(got.(map[string]any)["output"].(string), "retained-output") {
		t.Fatalf("completed session output lost: %#v, %v", got, err)
	}
}

func TestProcessStdinCloseSendsEOFAndRetainsOutput(t *testing.T) {
	x := testExecutor(t)
	var start map[string]any
	if runtime.GOOS == "windows" {
		start = map[string]any{"shell": "powershell", "command": "$text = [Console]::In.ReadToEnd(); [Console]::Out.Write('eof:' + $text)"}
	} else {
		start = map[string]any{"command": "sh", "args": []string{"-c", "value=$(cat); printf 'eof:%s' \"$value\""}}
	}
	started, err := x.Handle(context.Background(), "process.start", args(start))
	if err != nil {
		t.Fatal(err)
	}
	id := started.(map[string]any)["session_id"].(string)
	closed, err := x.Handle(context.Background(), "process.stdin", args(map[string]any{"session_id": id, "data": "payload", "close": true}))
	if err != nil {
		t.Fatal(err)
	}
	if closed.(map[string]any)["bytes_written"].(int) != len("payload") || !closed.(map[string]any)["closed"].(bool) {
		t.Fatalf("unexpected close result: %#v", closed)
	}
	if _, err = x.Handle(context.Background(), "process.stdin", args(map[string]any{"session_id": id, "close": true})); err == nil || !strings.Contains(err.Error(), "already closed") {
		t.Fatalf("duplicate close should fail, got %v", err)
	}
	if _, err = x.Handle(context.Background(), "process.stdin", args(map[string]any{"session_id": "wrong-session", "close": true})); err == nil || !strings.Contains(err.Error(), "unknown process session") {
		t.Fatalf("wrong session should fail, got %v", err)
	}
	_ = startQuickExit(t, x, "other-session")
	read, err := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "wait_seconds": 2}))
	if err != nil {
		t.Fatal(err)
	}
	state := read.(map[string]any)
	if state["running"].(bool) || state["output"].(string) != "eof:payload" {
		t.Fatalf("EOF did not finish process with retained output: %#v", state)
	}
}

func TestProcessStdinRejectsExitedSession(t *testing.T) {
	x := testExecutor(t)
	id := startQuickExit(t, x, "finished")
	if _, err := x.Handle(context.Background(), "process.stdin", args(map[string]any{"session_id": id, "data": "late input"})); err == nil || !strings.Contains(err.Error(), "process has exited") {
		t.Fatalf("stdin to exited process should fail, got %v", err)
	}
}

func TestSessionCapacityEvictsOnlyOldestFinished(t *testing.T) {
	x := testExecutor(t)
	old := startQuickExit(t, x, "old")
	x.mu.Lock()
	for i := 0; i < maxSessions-1; i++ {
		x.sessions["fake-"+strconv.Itoa(i)] = &session{exitCode: ptrInt(0), finished: time.Now().Add(time.Duration(i) * time.Second), done: closedChan(), output: &limitedBuffer{max: 8}}
	}
	x.mu.Unlock()
	newID := startQuickExit(t, x, "new")
	if x.get(old) != nil {
		t.Fatal("capacity eviction should evict oldest finished session")
	}
	if x.get(newID) == nil {
		t.Fatal("new session was not retained")
	}
	if len(x.sessions) > maxSessions {
		t.Fatalf("session map exceeded bound: %d", len(x.sessions))
	}
}

func ptrInt(v int) *int         { return &v }
func closedChan() chan struct{} { c := make(chan struct{}); close(c); return c }

func TestBoundedSearchAndExactReplace(t *testing.T) {
	x := testExecutor(t)
	root := x.Policy.AllowedRoots[0]
	file := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(file, []byte("alpha target\ntarget beta\n"), 0600); err != nil {
		t.Fatal(err)
	}
	search, err := x.Handle(context.Background(), "fs.search", args(map[string]any{"path": root, "text": "target", "max_matches": 1}))
	if err != nil {
		t.Fatal(err)
	}
	sv := search.(map[string]any)
	if reflect.ValueOf(sv["matches"]).Len() != 1 || !sv["truncated"].(bool) {
		t.Fatalf("unexpected bounded search: %#v", sv)
	}
	if _, err = x.Handle(context.Background(), "fs.replace", args(map[string]any{"path": file, "search": "target", "replace": "done", "expected_matches": 1})); err == nil {
		t.Fatal("mismatched match count should fail")
	}
	content, _ := os.ReadFile(file)
	if strings.Count(string(content), "target") != 2 {
		t.Fatal("file changed after match count mismatch")
	}
	if _, err = x.Handle(context.Background(), "fs.replace", args(map[string]any{"path": file, "search": "target", "replace": "done", "expected_matches": 2})); err != nil {
		t.Fatal(err)
	}
	content, _ = os.ReadFile(file)
	if strings.Count(string(content), "done") != 2 {
		t.Fatalf("replacement missing: %s", content)
	}
}

func TestSearchSkipsSymlinkEscape(t *testing.T) {
	x := testExecutor(t)
	root := x.Policy.AllowedRoots[0]
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("needle outside"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := x.Handle(context.Background(), "fs.search", args(map[string]any{"path": root, "text": "needle"}))
	if err != nil {
		t.Fatal(err)
	}
	if reflect.ValueOf(got.(map[string]any)["matches"]).Len() != 0 {
		t.Fatalf("search followed symlink outside allowed root: %#v", got)
	}
}

func TestSessionDiscoveryAndIndependentTimeout(t *testing.T) {
	x := testExecutor(t)
	defer x.Close()
	x.Policy.AllowedTools = append(x.Policy.AllowedTools, "process.sessions")
	x.Policy.MaxCommandRuntime = 250 * time.Millisecond
	x.Policy.MaxSessionRuntime = 5 * time.Second
	var a map[string]any
	if runtime.GOOS == "windows" {
		a = map[string]any{"shell": "powershell", "command": "$v=[Console]::In.ReadToEnd(); Start-Sleep -Milliseconds 700; Write-Output ('done:'+ $v)", "close_stdin": true}
	} else {
		a = map[string]any{"command": "sh", "args": []string{"-c", "v=$(cat); sleep 0.7; printf 'done:%s' \"$v\""}, "close_stdin": true}
	}
	result, err := x.Handle(context.Background(), "process.start", args(a))
	if err != nil {
		t.Fatal(err)
	}
	id := result.(map[string]any)["session_id"].(string)
	pid := result.(map[string]any)["pid"].(int)
	if pid <= 0 {
		t.Fatalf("bad pid: %d", pid)
	}
	listed, err := x.Handle(context.Background(), "process.sessions", args(map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(listed)
	if !strings.Contains(string(b), id) || !strings.Contains(string(b), strconv.Itoa(pid)) {
		t.Fatalf("session not discoverable: %s", b)
	}
	got, err := x.Handle(context.Background(), "process.read", args(map[string]any{"session_id": id, "wait_seconds": 4}))
	if err != nil {
		t.Fatal(err)
	}
	state := got.(map[string]any)
	if state["running"].(bool) || !strings.Contains(state["output"].(string), "done:") {
		t.Fatalf("early termination / missing EOF: %#v", state)
	}
}
