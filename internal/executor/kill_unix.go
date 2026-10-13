//go:build !windows

package executor

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func configureProcessTermination(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		if err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
