// Package executor contains platform-neutral tool dispatch and local policy checks.
package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
)

type Executor struct {
	Policy         policy.Policy
	Version        string
	Commit         string
	mu             sync.Mutex
	supervisorHost bool
	sessions       map[string]*session
}
type session struct {
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	stdinClosed bool
	cancel      context.CancelFunc
	output      *limitedBuffer
	done        chan struct{}
	exitCode    *int
	err         string
	created     time.Time
	finished    time.Time
	deadline    time.Time
	timeout     time.Duration
	exitReason  string
	terminated  bool
	shutdown    bool
	journal     *sessionJournal
	mu          sync.Mutex
}

const maxSessions = 64
const sessionRetention = 10 * time.Minute
const maxSearchFiles = 2000
const maxSearchDepth = 32
const maxSearchBytes = 16 << 20
const maxSearchMatches = 1000

type limitedBuffer struct {
	mu        sync.Mutex
	b         bytes.Buffer
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	room := b.max - b.b.Len()
	if room > 0 {
		if room > n {
			room = n
		}
		_, _ = b.b.Write(p[:room])
	}
	if room < n {
		b.truncated = true
	}
	return n, nil
}
func (b *limitedBuffer) String() string  { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func (b *limitedBuffer) Truncated() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.truncated }

func New(p policy.Policy, version string) *Executor {
	return &Executor{Policy: p, Version: version, sessions: make(map[string]*session)}
}

// Close cancels child process sessions when the agent service is shutting down.
func (x *Executor) Close() {
	x.mu.Lock()
	sessions := make([]*session, 0, len(x.sessions))
	for _, s := range x.sessions {
		sessions = append(sessions, s)
	}
	x.mu.Unlock()
	for _, s := range sessions {
		s.mu.Lock()
		s.shutdown = true
		s.mu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for _, s := range sessions {
		select {
		case <-s.done:
		case <-deadline.C:
			for _, remaining := range sessions {
				if remaining.cmd.Process != nil {
					_ = remaining.cmd.Process.Kill()
				}
			}
			return
		}
	}
}

func (x *Executor) Handle(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	if !x.Policy.ToolAllowed(method) {
		return nil, errors.New("tool is disabled by local policy")
	}
	if result, forwarded, err := x.supervisorDispatch(ctx, method, raw); forwarded {
		return result, err
	}
	switch method {
	case "system.info":
		return map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "hostname": hostname(), "agent_version": x.Version, "commit": x.Commit, "protocol_version": 1}, nil
	case "fs.list":
		var a struct {
			Path   string `json:"path"`
			Offset int    `json:"offset,omitempty"`
			Limit  int    `json:"limit,omitempty"`
		}
		if err := decode(raw, &a); err != nil {
			return nil, err
		}
		p, e := x.Policy.CheckPath(a.Path, false)
		if e != nil {
			return nil, e
		}
		if a.Offset < 0 || a.Offset > 10000 {
			return nil, errors.New("directory offset must be between 0 and 10000")
		}
		if a.Limit == 0 {
			a.Limit = 256
		}
		if a.Limit < 1 || a.Limit > 512 {
			return nil, errors.New("directory page limit must be between 1 and 512")
		}
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		entries, e := f.ReadDir(a.Offset + a.Limit + 1)
		if e != nil && e != io.EOF {
			return nil, e
		}
		type item struct {
			Name     string    `json:"name"`
			IsDir    bool      `json:"is_dir"`
			Size     int64     `json:"size"`
			Modified time.Time `json:"modified"`
		}
		start := a.Offset
		if start > len(entries) {
			start = len(entries)
		}
		end := start + a.Limit
		if end > len(entries) {
			end = len(entries)
		}
		out := make([]item, 0, end-start)
		for _, v := range entries[start:end] {
			info, er := v.Info()
			if er != nil {
				continue
			}
			out = append(out, item{v.Name(), v.IsDir(), info.Size(), info.ModTime().UTC()})
		}
		next := end
		if end < len(entries) {
			next = end
		}
		return map[string]any{"path": p, "entries": out, "offset": a.Offset, "next_offset": next, "has_more": end < len(entries)}, nil
	case "fs.read":
		var a struct {
			Path     string `json:"path"`
			MaxBytes int64  `json:"max_bytes,omitempty"`
		}
		if err := decode(raw, &a); err != nil {
			return nil, err
		}
		p, e := x.Policy.CheckPath(a.Path, false)
		if e != nil {
			return nil, e
		}
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		defer f.Close()
		lim := int64(x.Policy.MaxOutputBytes)
		if a.MaxBytes > 0 && a.MaxBytes < lim {
			lim = a.MaxBytes
		}
		b, e := io.ReadAll(io.LimitReader(f, lim+1))
		if e != nil {
			return nil, e
		}
		tr := int64(len(b)) > lim
		if tr {
			b = b[:lim]
		}
		return map[string]any{"path": p, "content": string(b), "truncated": tr}, nil
	case "fs.search":
		var a searchArgs
		if e := decode(raw, &a); e != nil {
			return nil, e
		}
		return x.search(a)
	case "fs.replace":
		var a replaceArgs
		if e := decode(raw, &a); e != nil {
			return nil, e
		}
		return x.replace(a)
	case "fs.write":
		var a struct {
			Path          string `json:"path"`
			Content       string `json:"content"`
			CreateParents bool   `json:"create_parents,omitempty"`
		}
		if err := decode(raw, &a); err != nil {
			return nil, err
		}
		p, e := x.Policy.CheckPath(a.Path, true)
		if e != nil {
			return nil, e
		}
		if len(a.Content) > x.Policy.MaxOutputBytes {
			return nil, errors.New("file content exceeds policy output limit")
		}
		if a.CreateParents {
			if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
				return nil, e
			}
		}
		if e = atomicWrite(p, []byte(a.Content)); e != nil {
			return nil, e
		}
		return map[string]any{"path": p, "bytes_written": len(a.Content)}, nil
	case "fs.mkdir":
		var a struct {
			Path    string `json:"path"`
			Parents bool   `json:"parents,omitempty"`
		}
		if e := decode(raw, &a); e != nil {
			return nil, e
		}
		p, e := x.Policy.CheckPath(a.Path, true)
		if e != nil {
			return nil, e
		}
		if a.Parents {
			e = os.MkdirAll(p, 0700)
		} else {
			e = os.Mkdir(p, 0700)
		}
		return map[string]any{"path": p, "created": e == nil}, e
	case "fs.move":
		var a struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if e := decode(raw, &a); e != nil {
			return nil, e
		}
		from, e := x.Policy.CheckPath(a.From, false)
		if e != nil {
			return nil, e
		}
		to, e := x.Policy.CheckPath(a.To, true)
		if e != nil {
			return nil, e
		}
		if e = os.Rename(from, to); e != nil {
			return nil, e
		}
		return map[string]any{"from": from, "to": to}, nil
	case "fs.stat":
		var a struct {
			Path string `json:"path"`
		}
		if e := decode(raw, &a); e != nil {
			return nil, e
		}
		p, e := x.Policy.CheckPath(a.Path, true)
		if e != nil {
			return nil, e
		}
		i, e := os.Stat(p)
		if os.IsNotExist(e) {
			return map[string]any{"path": p, "exists": false}, nil
		}
		if e != nil {
			return nil, e
		}
		return map[string]any{"path": p, "exists": true, "is_dir": i.IsDir(), "size": i.Size(), "modified": i.ModTime().UTC()}, nil
	case "process.run":
		return x.run(ctx, raw)
	case "process.start":
		return x.start(ctx, raw)
	case "process.read":
		return x.readSession(ctx, raw)
	case "process.sessions":
		return x.listSessions(), nil
	case "process.stdin":
		return x.stdin(raw)
	case "process.terminate":
		return x.terminate(raw)
	case "process.list":
		return listProcesses()
	case "process.kill":
		return x.killProcess(raw)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

type commandArgs struct {
	Command          string            `json:"command"`
	Args             []string          `json:"args,omitempty"`
	Shell            string            `json:"shell,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
	Stdin            string            `json:"stdin,omitempty"`
	CloseStdin       bool              `json:"close_stdin,omitempty"`
}

func (x *Executor) command(ctx context.Context, a commandArgs, background bool) (*exec.Cmd, context.Context, context.CancelFunc, error) {
	policyCommand := a.Command
	switch strings.ToLower(a.Shell) {
	case "powershell":
		policyCommand = "powershell.exe"
	case "pwsh":
		policyCommand = "pwsh"
	case "cmd":
		policyCommand = "cmd.exe"
	}
	if e := x.Policy.CheckCommand(policyCommand); e != nil {
		return nil, nil, nil, e
	}
	if a.Shell != "" {
		if e := x.Policy.CheckDeniedCommand(a.Command); e != nil {
			return nil, nil, nil, e
		}
	}
	if a.Shell != "" && !x.Policy.ToolAllowed("process.shell") {
		return nil, nil, nil, errors.New("shell execution is disabled by local policy")
	}
	if a.WorkingDirectory != "" {
		p, e := x.Policy.CheckPath(a.WorkingDirectory, false)
		if e != nil {
			return nil, nil, nil, e
		}
		a.WorkingDirectory = p
	}
	for k := range a.Environment {
		if strings.ContainsAny(k, "=\x00") || k == "" {
			return nil, nil, nil, fmt.Errorf("invalid environment variable name")
		}
	}
	timeout := x.Policy.MaxCommandRuntime
	if background && x.Policy.MaxSessionRuntime > 0 {
		timeout = x.Policy.MaxSessionRuntime
	}
	if a.TimeoutSeconds > 0 && time.Duration(a.TimeoutSeconds) < timeout/time.Second {
		timeout = time.Duration(a.TimeoutSeconds) * time.Second
	}
	if timeout <= 0 {
		return nil, nil, nil, errors.New("invalid timeout")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	var cmd *exec.Cmd
	switch strings.ToLower(a.Shell) {
	case "":
		cmd = exec.CommandContext(ctx, a.Command, a.Args...)
	case "powershell":
		if runtime.GOOS != "windows" {
			cancel()
			return nil, nil, nil, errors.New("PowerShell shell is only available on Windows")
		}
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", a.Command)
	case "pwsh":
		cmd = exec.CommandContext(ctx, "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", a.Command)
	case "cmd":
		if runtime.GOOS != "windows" {
			cancel()
			return nil, nil, nil, errors.New("cmd shell is only available on Windows")
		}
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", a.Command)
	default:
		cancel()
		return nil, nil, nil, errors.New("shell must be powershell, pwsh, or cmd")
	}
	if a.WorkingDirectory != "" {
		cmd.Dir = a.WorkingDirectory
	}
	if len(a.Environment) > 0 {
		cmd.Env = mergeEnvironment(os.Environ(), a.Environment, runtime.GOOS == "windows")
	}
	cmd.WaitDelay = 2 * time.Second
	configureProcessTermination(cmd)
	return cmd, ctx, cancel, nil
}

func (x *Executor) run(ctx context.Context, raw json.RawMessage) (any, error) {
	var a commandArgs
	if e := decode(raw, &a); e != nil {
		return nil, e
	}
	cmd, runCtx, cancel, e := x.command(ctx, a, false)
	if e != nil {
		return nil, e
	}
	defer cancel()
	stdout := &limitedBuffer{max: x.Policy.MaxOutputBytes}
	stderr := &limitedBuffer{max: x.Policy.MaxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if a.Stdin != "" {
		cmd.Stdin = strings.NewReader(a.Stdin)
	}
	start := time.Now()
	e = cmd.Run()
	exit := 0
	if runCtx.Err() != nil {
		return nil, fmt.Errorf("command timed out or was canceled: %w", runCtx.Err())
	}
	if e != nil {
		var ex *exec.ExitError
		if errors.As(e, &ex) {
			exit = ex.ExitCode()
		} else {
			return nil, e
		}
	}
	return map[string]any{"stdout": stdout.String(), "stderr": stderr.String(), "exit_code": exit, "duration_ms": time.Since(start).Milliseconds(), "stdout_truncated": stdout.Truncated(), "stderr_truncated": stderr.Truncated()}, nil
}

func (x *Executor) start(_ context.Context, raw json.RawMessage) (any, error) {
	var a commandArgs
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	cmd, runCtx, cancel, err := x.command(context.Background(), a, true)
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		cancel()
		return nil, err
	}
	journal, err := createSessionJournal(x.Policy, id)
	if err != nil {
		cancel()
		return nil, err
	}
	deadline, _ := runCtx.Deadline()
	created := time.Now()
	status := journalStatus{SessionID: id, Created: created, Deadline: deadline, TimeoutSeconds: int64(time.Until(deadline).Round(time.Second).Seconds()), State: "starting"}
	fail := func(cause error) (any, error) {
		cancel()
		if journal != nil {
			journal.close()
			status.State = "start_failed"
			status.ExitReason = "start_failed"
			status.LastError = cause.Error()
			_ = journal.record(status)
		}
		return nil, cause
	}
	if err = journal.record(status); err != nil {
		return fail(err)
	}
	out := &limitedBuffer{max: x.Policy.MaxOutputBytes}
	if journal != nil {
		cmd.Stdout = io.MultiWriter(out, journal)
		cmd.Stderr = io.MultiWriter(out, journal)
	} else {
		cmd.Stdout = out
		cmd.Stderr = out
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fail(err)
	}
	if err = cmd.Start(); err != nil {
		return fail(err)
	}
	status.PID = cmd.Process.Pid
	status.State = "running"
	if err = journal.record(status); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fail(err)
	}
	if a.CloseStdin {
		if err = stdin.Close(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fail(err)
		}
	}
	s := &session{cmd: cmd, stdin: stdin, stdinClosed: a.CloseStdin, cancel: cancel, output: out, done: make(chan struct{}), created: created, deadline: deadline, timeout: deadline.Sub(created), journal: journal}
	x.mu.Lock()
	x.pruneSessionsLocked(time.Now())
	if len(x.sessions) >= maxSessions {
		if !x.evictOldestFinishedLocked() {
			x.mu.Unlock()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fail(errors.New("process session limit reached"))
		}
	}
	x.sessions[id] = s
	x.mu.Unlock()
	go func() {
		defer cancel()
		waitErr := cmd.Wait()
		code := 0
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		s.mu.Lock()
		s.exitCode = &code
		s.finished = time.Now()
		switch {
		case s.terminated:
			s.exitReason = "explicit_terminate"
		case s.shutdown:
			s.exitReason = "agent_shutdown"
		case errors.Is(runCtx.Err(), context.DeadlineExceeded):
			s.exitReason = "deadline_exceeded"
		case errors.Is(runCtx.Err(), context.Canceled):
			s.exitReason = "context_canceled"
		case code == 0:
			s.exitReason = "exited_zero"
		default:
			s.exitReason = "exited_nonzero"
		}
		if waitErr != nil {
			s.err = waitErr.Error()
		}
		final := status
		final.State = "finished"
		final.ExitCode = s.exitCode
		final.Finished = &s.finished
		final.ExitReason = s.exitReason
		final.LastError = s.err
		s.mu.Unlock()
		if journal != nil {
			journal.close()
			if e := journal.record(final); e != nil {
				s.mu.Lock()
				s.err += "; journal final write: " + e.Error()
				s.mu.Unlock()
			}
		}
		close(s.done)
	}()
	recordPath, outputPath := journal.paths()
	return map[string]any{"session_id": id, "started": true, "pid": cmd.Process.Pid, "deadline": deadline, "timeout_seconds": status.TimeoutSeconds, "journal_status_path": recordPath, "journal_output_path": outputPath}, nil
}

func (x *Executor) pruneSessionsLocked(now time.Time) {
	for id, s := range x.sessions {
		s.mu.Lock()
		expired := s.exitCode != nil && now.Sub(s.finished) >= sessionRetention
		s.mu.Unlock()
		if expired {
			delete(x.sessions, id)
		}
	}
}

func (x *Executor) evictOldestFinishedLocked() bool {
	oldestID := ""
	var oldest time.Time
	for id, s := range x.sessions {
		s.mu.Lock()
		finished := s.exitCode != nil
		at := s.finished
		s.mu.Unlock()
		if finished && (oldestID == "" || at.Before(oldest)) {
			oldestID, oldest = id, at
		}
	}
	if oldestID == "" {
		return false
	}
	delete(x.sessions, oldestID)
	return true
}

type searchArgs struct {
	Path       string `json:"path"`
	Text       string `json:"text"`
	MaxFiles   int    `json:"max_files,omitempty"`
	MaxDepth   int    `json:"max_depth,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"`
}
type replaceArgs struct {
	Path            string `json:"path"`
	Search          string `json:"search"`
	Replace         string `json:"replace"`
	ExpectedMatches int    `json:"expected_matches"`
}

func (x *Executor) search(a searchArgs) (any, error) {
	if a.Text == "" {
		return nil, errors.New("search text is required")
	}
	files, depth, size, matches := a.MaxFiles, a.MaxDepth, a.MaxBytes, a.MaxMatches
	if files == 0 {
		files = 500
	}
	if files < 1 || files > maxSearchFiles {
		return nil, errors.New("max_files must be between 1 and 2000")
	}
	if depth == 0 {
		depth = 16
	}
	if depth < 0 || depth > maxSearchDepth {
		return nil, errors.New("max_depth must be between 0 and 32")
	}
	if size == 0 {
		size = 4 << 20
	}
	if size < 1 || size > maxSearchBytes {
		return nil, errors.New("max_bytes must be between 1 and 16777216")
	}
	if matches == 0 {
		matches = 100
	}
	if matches < 1 || matches > maxSearchMatches {
		return nil, errors.New("max_matches must be between 1 and 1000")
	}
	root, err := x.Policy.CheckPath(a.Path, false)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() {
		return x.searchFile(root, a.Text, int64(size), matches)
	}
	type match struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	found := make([]match, 0)
	scanned, consumed, truncated := 0, int64(0), false
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != root {
			rel, _ := filepath.Rel(root, path)
			level := strings.Count(rel, string(filepath.Separator)) + 1
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() && level > depth {
				return filepath.SkipDir
			}
		}
		if d.IsDir() {
			return nil
		}
		if scanned >= files || consumed >= size || len(found) >= matches {
			truncated = true
			return filepath.SkipAll
		}
		scanned++
		p, e := x.Policy.CheckPath(path, false)
		if e != nil {
			if strings.Contains(e.Error(), "denied") {
				return nil
			}
			return e
		}
		info, e := os.Stat(p)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > size-consumed {
			truncated = true
			return filepath.SkipAll
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		consumed += int64(len(data))
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, a.Text) {
				found = append(found, match{p, i + 1, line})
				if len(found) >= matches {
					truncated = true
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"matches": found, "files_scanned": scanned, "bytes_scanned": consumed, "truncated": truncated}, nil
}

func (x *Executor) searchFile(path, text string, maxBytes int64, maxMatches int) (any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("search path must be a regular file or directory")
	}
	if info.Size() > maxBytes {
		return nil, errors.New("file exceeds search byte limit")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	type match struct {
		Path string `json:"path"`
		Line int    `json:"line"`
		Text string `json:"text"`
	}
	out := make([]match, 0)
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if strings.Contains(line, text) {
			out = append(out, match{path, i + 1, line})
			if len(out) == maxMatches {
				break
			}
		}
	}
	return map[string]any{"matches": out, "files_scanned": 1, "bytes_scanned": len(b), "truncated": len(out) == maxMatches}, nil
}

func (x *Executor) replace(a replaceArgs) (any, error) {
	if a.Search == "" {
		return nil, errors.New("search text is required")
	}
	if a.ExpectedMatches < 1 || a.ExpectedMatches > maxSearchMatches {
		return nil, errors.New("expected_matches must be between 1 and 1000")
	}
	p, err := x.Policy.CheckPath(a.Path, false)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("replace path must be a regular file")
	}
	if info.Size() > maxSearchBytes {
		return nil, errors.New("file exceeds replace byte limit")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	count := strings.Count(string(b), a.Search)
	if count != a.ExpectedMatches {
		return nil, fmt.Errorf("expected %d matches, found %d; file unchanged", a.ExpectedMatches, count)
	}
	updated := strings.ReplaceAll(string(b), a.Search, a.Replace)
	if len(updated) > x.Policy.MaxOutputBytes {
		return nil, errors.New("replacement result exceeds policy output limit")
	}
	if err = atomicWrite(p, []byte(updated)); err != nil {
		return nil, err
	}
	return map[string]any{"path": p, "matches_replaced": count, "bytes_written": len(updated)}, nil
}
func (x *Executor) listSessions() map[string]any {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneSessionsLocked(time.Now())
	type item struct {
		SessionID         string    `json:"session_id"`
		PID               int       `json:"pid"`
		Created           time.Time `json:"created"`
		Running           bool      `json:"running"`
		ExitCode          *int      `json:"exit_code"`
		Deadline          time.Time `json:"deadline"`
		ExitReason        string    `json:"exit_reason,omitempty"`
		JournalStatusPath string    `json:"journal_status_path,omitempty"`
		JournalOutputPath string    `json:"journal_output_path,omitempty"`
	}
	out := make([]item, 0, len(x.sessions))
	for id, s := range x.sessions {
		s.mu.Lock()
		statusPath, outputPath := s.journal.paths()
		v := item{SessionID: id, PID: s.cmd.Process.Pid, Created: s.created, Running: s.exitCode == nil, ExitCode: s.exitCode, Deadline: s.deadline, ExitReason: s.exitReason, JournalStatusPath: statusPath, JournalOutputPath: outputPath}
		s.mu.Unlock()
		out = append(out, v)
	}
	for _, st := range x.archivedJournalStatuses() {
		if _, inMemory := x.sessions[st.SessionID]; inMemory {
			continue
		}
		reason := st.ExitReason
		if st.State != "finished" && st.State != "start_failed" {
			reason = "unknown_after_agent_restart"
		}
		out = append(out, item{SessionID: st.SessionID, PID: st.PID, Created: st.Created, Running: false, ExitCode: st.ExitCode, Deadline: st.Deadline, ExitReason: reason, JournalStatusPath: filepath.Join(x.Policy.SessionJournalDir, st.SessionID, "status.json"), JournalOutputPath: filepath.Join(x.Policy.SessionJournalDir, st.SessionID, "output.log")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	if len(out) > 128 {
		out = out[:128]
	}
	return map[string]any{"sessions": out}
}

func (x *Executor) readSession(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		SessionID   string `json:"session_id"`
		WaitSeconds int    `json:"wait_seconds,omitempty"`
		Offset      int    `json:"offset,omitempty"`
	}
	if e := decode(raw, &a); e != nil {
		return nil, e
	}
	if a.WaitSeconds < 0 || a.WaitSeconds > 30 {
		return nil, errors.New("wait_seconds must be between 0 and 30")
	}
	s := x.get(a.SessionID)
	if s == nil {
		return x.readArchivedSession(a.SessionID, a.Offset)
	}
	if a.WaitSeconds > 0 {
		select {
		case <-s.done:
		case <-time.After(time.Duration(a.WaitSeconds) * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	output := s.output.String()
	if a.Offset < 0 || a.Offset > len(output) {
		return nil, errors.New("offset is outside available output")
	}
	statusPath, outputPath := s.journal.paths()
	end := a.Offset + 64<<10
	if end > len(output) || end < a.Offset {
		end = len(output)
	}
	return map[string]any{"session_id": a.SessionID, "output": output[a.Offset:end], "next_offset": end, "running": s.exitCode == nil, "exit_code": s.exitCode, "exit_reason": s.exitReason, "deadline": s.deadline, "journal_status_path": statusPath, "journal_output_path": outputPath, "error": s.err, "truncated": s.output.Truncated(), "output_has_more": end < len(output)}, nil
}

type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

func listProcesses() (any, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tasklist.exe", "/FO", "CSV", "/NH")
	} else {
		cmd = exec.Command("ps", "-eo", "pid=,comm=")
	}
	b, e := cmd.Output()
	if e != nil {
		return nil, e
	}
	out := make([]ProcessInfo, 0, 128)
	if runtime.GOOS == "windows" {
		r := csv.NewReader(bytes.NewReader(b))
		r.FieldsPerRecord = -1
		for len(out) < 512 {
			rec, e := r.Read()
			if e == io.EOF {
				break
			}
			if e != nil || len(rec) < 2 {
				continue
			}
			pid, er := strconv.Atoi(strings.TrimSpace(rec[1]))
			if er != nil {
				continue
			}
			out = append(out, ProcessInfo{PID: pid, Name: rec[0]})
		}
	} else {
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, e := strconv.Atoi(fields[0])
			if e == nil {
				out = append(out, ProcessInfo{PID: pid, Name: fields[1]})
				if len(out) >= 512 {
					break
				}
			}
		}
	}
	return map[string]any{"processes": out, "truncated": len(out) >= 512}, nil
}
func (x *Executor) killProcess(raw json.RawMessage) (any, error) {
	var a struct {
		PID int `json:"pid"`
	}
	if e := decode(raw, &a); e != nil {
		return nil, e
	}
	if a.PID < 5 || a.PID == os.Getpid() {
		return nil, errors.New("refusing to terminate a protected process")
	}
	v, e := listProcesses()
	if e != nil {
		return nil, e
	}
	m := v.(map[string]any)
	items := m["processes"].([]ProcessInfo)
	name := ""
	for _, p := range items {
		if p.PID == a.PID {
			name = p.Name
			break
		}
	}
	if name == "" {
		return nil, errors.New("process was not found")
	}
	for _, d := range x.Policy.DeniedProcessNames {
		if strings.EqualFold(name, d) || strings.EqualFold(filepath.Base(name), filepath.Base(d)) {
			return nil, errors.New("process is denied by local policy")
		}
	}
	for _, d := range []string{"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe"} {
		if strings.EqualFold(name, d) {
			return nil, errors.New("process is protected by built-in policy")
		}
	}
	proc, e := os.FindProcess(a.PID)
	if e != nil {
		return nil, e
	}
	if e = proc.Kill(); e != nil {
		return nil, e
	}
	return map[string]any{"pid": a.PID, "name": name, "terminated": true}, nil
}
func (x *Executor) stdin(raw json.RawMessage) (any, error) {
	var a struct {
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
		Close     bool   `json:"close,omitempty"`
	}
	if e := decode(raw, &a); e != nil {
		return nil, e
	}
	s := x.get(a.SessionID)
	if s == nil {
		return nil, errors.New("unknown process session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stdinClosed {
		return nil, errors.New("process stdin is already closed")
	}
	if s.exitCode != nil {
		return nil, errors.New("process has exited")
	}
	if s.stdin == nil {
		return nil, errors.New("process was not started with stdin support")
	}
	written, e := io.WriteString(s.stdin, a.Data)
	if e != nil {
		return nil, e
	}
	if a.Close {
		if e = s.stdin.Close(); e != nil {
			return nil, e
		}
		s.stdinClosed = true
	}
	return map[string]any{"bytes_written": written, "closed": s.stdinClosed}, nil
}
func (x *Executor) terminate(raw json.RawMessage) (any, error) {
	var a struct {
		SessionID string `json:"session_id"`
	}
	if e := decode(raw, &a); e != nil {
		return nil, e
	}
	s := x.get(a.SessionID)
	if s == nil {
		return nil, errors.New("unknown process session")
	}
	s.mu.Lock()
	if s.exitCode == nil {
		s.terminated = true
	}
	s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	select {
	case <-s.done:
		return map[string]any{"terminated": true}, nil
	case <-time.After(3 * time.Second):
	}
	if s.cmd.Process == nil {
		return map[string]any{"terminated": false}, nil
	}
	e := s.cmd.Process.Kill()
	if errors.Is(e, os.ErrProcessDone) {
		e = nil
	}
	return map[string]any{"terminated": e == nil}, e
}
func (x *Executor) get(id string) *session { x.mu.Lock(); defer x.mu.Unlock(); return x.sessions[id] }
func decode(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return errors.New("arguments are required")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
func atomicWrite(path string, data []byte) error {
	tmp, e := os.CreateTemp(filepath.Dir(path), ".ato-write-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(data); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Sync(); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func mergeEnvironment(base []string, overrides map[string]string, caseInsensitive bool) []string {
	index := make(map[string]int, len(base))
	canon := func(k string) string {
		if caseInsensitive {
			return strings.ToUpper(k)
		}
		return k
	}
	for i, e := range base {
		if k, _, ok := strings.Cut(e, "="); ok {
			index[canon(k)] = i
		}
	}
	out := append([]string(nil), base...)
	for k, v := range overrides {
		kv := k + "=" + v
		if i, ok := index[canon(k)]; ok {
			out[i] = kv
		} else {
			index[canon(k)] = len(out)
			out = append(out, kv)
		}
	}
	return out
}
func hostname() string { h, _ := os.Hostname(); return h }
func newID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
