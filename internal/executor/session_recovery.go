package executor

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Persisted journals remain discoverable after the in-memory cache expires.
// An old "running" status is NOT proof that its PID is still running.
func (x *Executor) archivedJournalStatuses() []journalStatus {
	root := x.Policy.SessionJournalDir
	if root == "" {
		return nil
	}
	base, err := x.Policy.CheckPath(root, false)
	if err != nil {
		return nil
	}
	dirs, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	out := make([]journalStatus, 0, len(dirs))
	for _, d := range dirs {
		id := d.Name()
		if !d.IsDir() || !validSessionID(id) {
			continue
		}
		st, err := x.archivedStatus(id)
		if err == nil {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	if len(out) > 128 {
		out = out[:128]
	}
	return out
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (x *Executor) archivedStatus(id string) (journalStatus, error) {
	var st journalStatus
	if !validSessionID(id) || x.Policy.SessionJournalDir == "" {
		return st, errors.New("unknown process session")
	}
	p, err := x.Policy.CheckPath(filepath.Join(x.Policy.SessionJournalDir, id, "status.json"), false)
	if err != nil {
		return st, errors.New("unknown process session")
	}
	f, err := os.Open(p)
	if err != nil {
		return st, errors.New("unknown process session")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(b) > 16384 {
		return st, errors.New("invalid session status")
	}
	if err = json.Unmarshal(b, &st); err != nil || st.SessionID != id || st.Created.IsZero() {
		return st, errors.New("invalid session status")
	}
	return st, nil
}

// Output pages remain bounded even when the persisted journal is larger.
// Unfinished status after restart is reported as uncertain and non-live.
func (x *Executor) readArchivedSession(id string, offset int) (any, error) {
	st, err := x.archivedStatus(id)
	if err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, errors.New("negative session output offset")
	}
	p, err := x.Policy.CheckPath(filepath.Join(x.Policy.SessionJournalDir, id, "output.log"), false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("session output must be a regular file")
	}
	if int64(offset) > info.Size() {
		return nil, errors.New("offset is outside available output")
	}
	if _, err = f.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, err
	}
	page := x.Policy.MaxOutputBytes
	if page <= 0 || page > 64<<10 {
		page = 64 << 10
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(page)))
	if err != nil {
		return nil, err
	}
	reason := st.ExitReason
	if st.State != "finished" && st.State != "start_failed" {
		reason = "unknown_after_agent_restart"
	}
	return map[string]any{"session_id": id, "output": string(b), "next_offset": offset + len(b), "running": false, "exit_code": st.ExitCode, "exit_reason": reason, "deadline": st.Deadline, "journal_status_path": filepath.Join(x.Policy.SessionJournalDir, id, "status.json"), "journal_output_path": p, "error": st.LastError, "truncated": st.OutputTruncated, "archived": true, "output_has_more": int64(offset+len(b)) < info.Size(), "state_uncertain": reason == "unknown_after_agent_restart"}, nil
}
