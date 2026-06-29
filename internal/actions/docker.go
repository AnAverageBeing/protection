package actions

import (
	"context"
	"fmt"

	"protection/internal/core"
	"protection/internal/docker"
)

// KillContainer SIGKILLs the offending container — the fastest way to stop an
// active miner, flood or exploit.
type KillContainer struct {
	docker *docker.Client
}

func (a *KillContainer) Name() string { return "kill_container" }

func (a *KillContainer) Execute(ctx context.Context, ev core.Event) error {
	if ev.ContainerID == "" {
		return fmt.Errorf("kill_container: event has no container id")
	}
	return a.docker.Kill(ctx, ev.ContainerID)
}

// StopContainer gracefully stops the offending container.
type StopContainer struct {
	docker *docker.Client
}

func (a *StopContainer) Name() string { return "stop_container" }

func (a *StopContainer) Execute(ctx context.Context, ev core.Event) error {
	if ev.ContainerID == "" {
		return fmt.Errorf("stop_container: event has no container id")
	}
	return a.docker.Stop(ctx, ev.ContainerID)
}
