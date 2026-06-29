package actions

import (
	"context"
	"fmt"
	"syscall"

	"protection/internal/core"
	"protection/internal/docker"
	"protection/internal/logging"
)

// Neutralize is the smart "stop this threat" action. It picks the right tool
// for the target automatically:
//   - containerised threat + Docker available → kill the container
//   - otherwise (bare-VPS host process)       → SIGKILL the process
//
// This is what the default rules use, so one policy line works on Pterodactyl/
// Docker nodes and plain VPS hosts alike.
type Neutralize struct {
	docker *docker.Client
}

func (a *Neutralize) Name() string { return "neutralize" }

func (a *Neutralize) Execute(ctx context.Context, ev core.Event) error {
	if ev.ContainerID != "" && a.docker != nil {
		if err := a.docker.Kill(ctx, ev.ContainerID); err != nil {
			return fmt.Errorf("neutralize: kill container: %w", err)
		}
		logging.Info("neutralized container %s", ev.Target())
		return nil
	}
	if ev.PID > 1 {
		if err := syscall.Kill(ev.PID, syscall.SIGKILL); err != nil {
			return fmt.Errorf("neutralize: kill pid %d: %w", ev.PID, err)
		}
		logging.Info("neutralized process pid %d (%s)", ev.PID, ev.Process)
		return nil
	}
	return fmt.Errorf("neutralize: nothing actionable (no container id, pid=%d)", ev.PID)
}
