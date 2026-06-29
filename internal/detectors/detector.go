// Package detectors implements the threat-detection engine. Each detector is an
// independent unit that periodically inspects the system and emits core.Events.
package detectors

import (
	"context"
	"sync"
	"time"

	"protection/internal/core"
	"protection/internal/docker"
	"protection/internal/system"
)

// Detector inspects the system and returns any security events it finds. Run is
// called on the engine's scan interval with a shared system snapshot (gathered
// once per tick) and must return within roughly one interval.
type Detector interface {
	Name() string
	Run(ctx context.Context, snap *system.Snapshot) ([]core.Event, error)
}

// containerResolver caches container-id → metadata lookups so detectors can
// cheaply annotate events with the container name and pterodactyl server uuid.
type containerResolver struct {
	docker *docker.Client

	mu     sync.Mutex
	cache  map[string]containerMeta
	expiry time.Time
}

type containerMeta struct {
	name   string
	server string // pterodactyl server uuid, derived from labels/name
}

func newContainerResolver(d *docker.Client) *containerResolver {
	return &containerResolver{docker: d, cache: map[string]containerMeta{}}
}

// resolve annotates an event in place with container name/server when a
// container id is present. Safe to call with a nil docker client.
func (r *containerResolver) resolve(ctx context.Context, ev *core.Event) {
	if r == nil || r.docker == nil || ev.ContainerID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Now().After(r.expiry) {
		r.refresh(ctx)
	}
	if meta, ok := r.cache[ev.ContainerID]; ok {
		ev.Container = meta.name
		if ev.Server == "" {
			ev.Server = meta.server
		}
	}
}

func (r *containerResolver) refresh(ctx context.Context) {
	list, err := r.docker.ListContainers(ctx)
	if err != nil {
		return
	}
	fresh := make(map[string]containerMeta, len(list))
	for _, c := range list {
		fresh[c.ID] = containerMeta{
			name:   c.Name(),
			server: pteroServerUUID(c),
		}
	}
	r.cache = fresh
	r.expiry = time.Now().Add(30 * time.Second)
}

// pteroServerUUID extracts a Pterodactyl server uuid from container metadata.
// Wings labels containers and names them by the server's short uuid.
func pteroServerUUID(c docker.Container) string {
	for _, key := range []string{"Service", "uuid", "ServerUUID"} {
		if v, ok := c.Labels[key]; ok && v != "" {
			return v
		}
	}
	// Wings container names are the server short-uuid (e.g. "a1b2c3d4").
	return c.Name()
}
