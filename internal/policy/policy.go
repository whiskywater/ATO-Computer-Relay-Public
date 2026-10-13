// Package policy enforces the agent-local authority boundary.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Policy struct {
	AllowedRoots           []string      `json:"allowed_roots"`
	DeniedPaths            []string      `json:"denied_paths,omitempty"`
	AllowedTools           []string      `json:"allowed_tools"`
	AllowedCommands        []string      `json:"allowed_commands,omitempty"`
	DeniedCommands         []string      `json:"denied_commands,omitempty"`
	DeniedProcessNames     []string      `json:"denied_process_names,omitempty"`
	MaxSessionRuntime      time.Duration `json:"max_session_runtime,omitempty"`
	SupervisorEnabled      bool          `json:"session_supervisor_enabled,omitempty"`
	SessionJournalDir      string        `json:"session_journal_dir,omitempty"`
	MaxSessionJournalBytes int64         `json:"max_session_journal_bytes,omitempty"`
	MaxCommandRuntime      time.Duration `json:"max_command_runtime"`
	MaxOutputBytes         int           `json:"max_output_bytes"`
}

func (p Policy) Validate() error {
	if len(p.AllowedRoots) == 0 {
		return errors.New("at least one allowed filesystem root is required")
	}
	if len(p.AllowedTools) == 0 {
		return errors.New("at least one tool must be allowed")
	}
	if p.MaxCommandRuntime <= 0 || p.MaxCommandRuntime > 30*time.Minute {
		return errors.New("max command runtime must be between 1ns and 30m")
	}
	if p.MaxSessionJournalBytes < 0 || p.MaxSessionJournalBytes > 32<<20 || (p.MaxSessionJournalBytes > 0 && p.MaxSessionJournalBytes < 1024) {
		return errors.New("session journal byte cap must be 0 or between 1 KiB and 32 MiB")
	}
	if p.SessionJournalDir != "" {
		if _, err := p.CheckPath(p.SessionJournalDir, true); err != nil {
			return fmt.Errorf("session journal directory denied: %w", err)
		}
	}
	if p.MaxSessionRuntime < 0 || p.MaxSessionRuntime > 24*time.Hour {
		return errors.New("max session runtime must be between 0 and 24h")
	}
	if p.MaxOutputBytes < 1024 || p.MaxOutputBytes > 256<<10 {
		return errors.New("max output bytes must be between 1 KiB and 256 KiB")
	}
	return nil
}

func (p Policy) ToolAllowed(tool string) bool {
	for _, t := range p.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}

func (p Policy) CheckPath(path string, allowMissing bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	resolved, err := resolvePath(abs, allowMissing)
	if err != nil {
		return "", err
	}
	for _, denied := range p.DeniedPaths {
		d, e := filepath.Abs(filepath.Clean(denied))
		if e != nil {
			continue
		}
		d, _ = resolvePath(d, true)
		if within(d, resolved) {
			return "", fmt.Errorf("path is denied by local policy")
		}
	}
	for _, root := range p.AllowedRoots {
		r, e := filepath.Abs(filepath.Clean(root))
		if e != nil {
			continue
		}
		r, _ = resolvePath(r, true)
		if within(r, resolved) {
			return resolved, nil
		}
	}
	return "", errors.New("path is outside allowed filesystem roots")
}

func (p Policy) CheckCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("command is required")
	}
	if len(p.AllowedCommands) > 0 {
		base := strings.ToLower(filepath.Base(command))
		allowed := false
		for _, entry := range p.AllowedCommands {
			if filepath.IsAbs(entry) {
				// An absolute entry is a pinned executable, not a basename wildcard.
				if filepath.IsAbs(command) && strings.EqualFold(filepath.Clean(command), filepath.Clean(entry)) {
					allowed = true
					break
				}
			} else if base == strings.ToLower(filepath.Base(entry)) || strings.EqualFold(command, entry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("executable is not in the local allowlist")
		}
	}
	return p.CheckDeniedCommand(command)
}

func (p Policy) CheckDeniedCommand(command string) error {
	lower := strings.ToLower(command)
	for _, s := range p.DeniedCommands {
		if s != "" && strings.Contains(lower, strings.ToLower(s)) {
			return errors.New("command denied by local policy")
		}
	}
	return nil
}

func within(root, target string) bool {
	r, _ := filepath.Abs(root)
	t, _ := filepath.Abs(target)
	rel, err := filepath.Rel(r, t)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func resolvePath(path string, allowMissing bool) (string, error) {
	if _, err := os.Lstat(path); err == nil {
		return filepath.EvalSymlinks(path)
	} else if !allowMissing || !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	resolvedParent, err := resolvePath(parent, true)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), nil
}
