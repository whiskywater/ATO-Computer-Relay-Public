//go:build windows

package executor

import (
	"os"
	"os/exec"
	"strconv"
)

func configureProcessTermination(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := exec.Command("taskkill.exe", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
		if err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
