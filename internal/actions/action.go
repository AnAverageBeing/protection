// Package actions performs enforcement in response to security events: killing
// containers, quarantining files, suspending Pterodactyl servers and more.
// Every action honours the daemon's global dry-run switch.
package actions

import (
	"context"
	"fmt"

	"protection/internal/config"
	"protection/internal/core"
	"protection/internal/docker"
	"protection/internal/logging"
)

// Action performs one enforcement step for an event.
type Action interface {
	Name() string
	Execute(ctx context.Context, ev core.Event) error
}

// Registry maps action names (as referenced by rules) to implementations.
type Registry struct {
	actions map[string]Action
	dryRun  bool
}

// NewRegistry wires up every enabled action backend from config.
func NewRegistry(cfg *config.Config, dockerClient *docker.Client) *Registry {
	r := &Registry{actions: map[string]Action{}, dryRun: cfg.General.DryRun}

	if cfg.Actions.Docker.Enabled && dockerClient != nil {
		r.register(&KillContainer{docker: dockerClient})
		r.register(&StopContainer{docker: dockerClient})
	}
	if cfg.Actions.File.Enabled {
		r.register(&QuarantineFile{dir: cfg.Actions.File.QuarantineDir})
		r.register(&DeleteFile{})
	}
	// kill_process and the smart neutralize action need no backend config;
	// neutralize falls back to process-kill when Docker is unavailable.
	r.register(&KillProcess{})
	r.register(&Neutralize{docker: dockerClient})

	if cfg.Actions.Pterodactyl.Enabled {
		r.register(NewSuspendServer(cfg.Actions.Pterodactyl))
	}
	return r
}

func (r *Registry) register(a Action) { r.actions[a.Name()] = a }

// Has reports whether an action name is available.
func (r *Registry) Has(name string) bool {
	_, ok := r.actions[name]
	return ok
}

// Run executes a named action for an event, respecting dry-run mode. The
// special names "alert" and "log_only" are no-ops here (handled by the engine).
func (r *Registry) Run(ctx context.Context, name string, ev core.Event) error {
	switch name {
	case "alert", "log_only", "":
		return nil
	}
	a, ok := r.actions[name]
	if !ok {
		return fmt.Errorf("action %q is not enabled or does not exist", name)
	}
	if r.dryRun {
		logging.Warn("[dry-run] would run action %q on %s", name, ev.Target())
		return nil
	}
	logging.Info("running action %q on %s", name, ev.Target())
	return a.Execute(ctx, ev)
}
