//go:build !windows

package agent

import "context"

func IsWindowsService() bool { return false }
func RunWindowsService(_ string, run func(context.Context) error) error {
	return run(context.Background())
}
