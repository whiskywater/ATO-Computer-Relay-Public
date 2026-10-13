package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPathRootsAndDeniedSubtree(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	denied := filepath.Join(allowed, "private")
	if err := os.MkdirAll(denied, 0700); err != nil {
		t.Fatal(err)
	}
	p := Policy{AllowedRoots: []string{allowed}, DeniedPaths: []string{denied}, AllowedTools: []string{"fs.read"}, MaxCommandRuntime: time.Minute, MaxOutputBytes: 1024}
	if _, err := p.CheckPath(filepath.Join(allowed, "new.txt"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := p.CheckPath(filepath.Join(denied, "secret.txt"), true); err == nil {
		t.Fatal("denied subtree allowed")
	}
	if _, err := p.CheckPath(filepath.Join(root, "outside"), true); err == nil {
		t.Fatal("path outside roots allowed")
	}
}
func TestCommandAllowAndDeny(t *testing.T) {
	p := Policy{AllowedCommands: []string{"powershell.exe"}, DeniedCommands: []string{"Remove-Item"}}
	if err := p.CheckCommand(`powershell.exe`); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckCommand("whoami.exe"); err == nil {
		t.Fatal("command outside allowlist allowed")
	}
	p.AllowedCommands = nil
	if err := p.CheckCommand(`Write-Output 'x'; Remove-Item file`); err == nil {
		t.Fatal("denied command pattern allowed")
	}
}
func TestValidateBounds(t *testing.T) {
	p := Policy{AllowedRoots: []string{"."}, AllowedTools: []string{"system.info"}, MaxCommandRuntime: 31 * time.Minute, MaxOutputBytes: 1024}
	if p.Validate() == nil {
		t.Fatal("accepted excessive runtime")
	}
}

func TestPinnedAbsoluteExecutableDoesNotPermitSameBasenameElsewhere(t *testing.T) {
	trusted := filepath.Join(t.TempDir(), "trusted", "codex.exe")
	p := Policy{AllowedCommands: []string{trusted}}
	if err := p.CheckCommand(trusted); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "untrusted", "codex.exe")
	if err := p.CheckCommand(other); err == nil {
		t.Fatal("absolute pinned command was bypassed using the same basename")
	}
	if err := p.CheckCommand("codex.exe"); err == nil {
		t.Fatal("bare basename bypassed absolute path entry")
	}
}
