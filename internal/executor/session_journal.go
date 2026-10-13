package executor

import (
	"encoding/json"
	"fmt"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Journal output is potentially sensitive; no prompts, argv or environment in status.
type sessionJournal struct {
	mu        sync.Mutex
	dir       string
	output    *os.File
	limit     int64
	written   int64
	truncated bool
	writeErr  string
	lastSync  time.Time
}
type journalStatus struct {
	SessionID       string     `json:"session_id"`
	PID             int        `json:"pid"`
	Created         time.Time  `json:"created"`
	Deadline        time.Time  `json:"deadline"`
	TimeoutSeconds  int64      `json:"timeout_seconds"`
	State           string     `json:"state"`
	ExitReason      string     `json:"exit_reason,omitempty"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	Finished        *time.Time `json:"finished,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	OutputBytes     int64      `json:"output_bytes"`
	OutputTruncated bool       `json:"output_truncated"`
	JournalError    string     `json:"journal_error,omitempty"`
}

func createSessionJournal(p policy.Policy, id string) (*sessionJournal, error) {
	if p.SessionJournalDir == "" {
		return nil, nil
	}
	base, err := p.CheckPath(p.SessionJournalDir, true)
	if err != nil {
		return nil, fmt.Errorf("journal path denied: %w", err)
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	dir := filepath.Join(base, id)
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "output.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	lim := p.MaxSessionJournalBytes
	if lim == 0 {
		lim = 8 << 20
	}
	return &sessionJournal{dir: dir, output: f, limit: lim}, nil
}
func (j *sessionJournal) Write(data []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	room := j.limit - j.written
	n := len(data)
	if room < int64(n) {
		j.truncated = true
		if room < 0 {
			room = 0
		}
		n = int(room)
	}
	if n > 0 && j.writeErr == "" {
		written, err := j.output.Write(data[:n])
		j.written += int64(written)
		if err != nil {
			j.writeErr = err.Error()
		}
		if err == nil && time.Since(j.lastSync) > 2*time.Second {
			if e := j.output.Sync(); e != nil {
				j.writeErr = e.Error()
			}
			j.lastSync = time.Now()
		}
	}
	return len(data), nil
}
func (j *sessionJournal) paths() (string, string) {
	if j == nil {
		return "", ""
	}
	return filepath.Join(j.dir, "status.json"), filepath.Join(j.dir, "output.log")
}
func (j *sessionJournal) snapshot(s journalStatus) journalStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	s.OutputBytes = j.written
	s.OutputTruncated = j.truncated
	s.JournalError = j.writeErr
	return s
}
func (j *sessionJournal) record(s journalStatus) error {
	if j == nil {
		return nil
	}
	s = j.snapshot(s)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(j.dir, "status.json"), append(b, '\n'))
}
func (j *sessionJournal) close() {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.output != nil {
		if e := j.output.Sync(); e != nil && j.writeErr == "" {
			j.writeErr = e.Error()
		}
		if e := j.output.Close(); e != nil && j.writeErr == "" {
			j.writeErr = e.Error()
		}
		j.output = nil
	}
}
