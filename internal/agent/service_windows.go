//go:build windows

package agent

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows/svc"
)

func IsWindowsService() bool { yes, err := svc.IsWindowsService(); return err == nil && yes }

func RunWindowsService(name string, run func(context.Context) error) error {
	return svc.Run(name, &serviceHandler{run: run})
}

type serviceHandler struct{ run func(context.Context) error }

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						return false, 1
					}
					status <- svc.Status{State: svc.Stopped}
					return false, 0
				case <-time.After(15 * time.Second):
					return false, 1
				}
			}
		case err := <-done:
			if err != nil {
				return false, 1
			}
			status <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}
