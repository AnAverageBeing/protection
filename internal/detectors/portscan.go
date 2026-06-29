package detectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"protection/internal/config"
	"protection/internal/core"
	"protection/internal/docker"
	"protection/internal/system"
)

// PortScanDetector identifies port-scanning behaviour. A scanner fans out many
// half-open (SYN_SENT) connections to many ports/hosts in a short window. We
// accumulate distinct destinations per process across a sliding window and also
// match known scanner binaries.
type PortScanDetector struct {
	cfg      config.PortScanConfig
	resolver *containerResolver
	scanners map[string]bool

	state map[int]*scanState
}

type scanState struct {
	comm        string
	containerID string
	ports       map[int]time.Time
	hosts       map[string]time.Time
}

// NewPortScanDetector builds a port-scan detector from config.
func NewPortScanDetector(cfg config.PortScanConfig, d *docker.Client) *PortScanDetector {
	sc := make(map[string]bool, len(cfg.KnownScannerProcs))
	for _, n := range cfg.KnownScannerProcs {
		sc[strings.ToLower(n)] = true
	}
	return &PortScanDetector{
		cfg:      cfg,
		resolver: newContainerResolver(d),
		scanners: sc,
		state:    map[int]*scanState{},
	}
}

func (d *PortScanDetector) Name() string { return "portscan" }

func (d *PortScanDetector) Run(ctx context.Context, snap *system.Snapshot) ([]core.Event, error) {
	now := snap.Time

	for _, c := range snap.Conns {
		if c.PID == 0 || !c.SynSent() {
			continue
		}
		st := d.state[c.PID]
		if st == nil {
			st = &scanState{comm: c.Process, containerID: c.ContainerID, ports: map[int]time.Time{}, hosts: map[string]time.Time{}}
			d.state[c.PID] = st
		}
		if st.containerID == "" {
			st.containerID = c.ContainerID
		}
		st.ports[c.RemotePort] = now
		if c.RemoteIP != nil {
			st.hosts[c.RemoteIP.String()] = now
		}
	}

	var events []core.Event
	for pid, st := range d.state {
		prunePortState(st, now, d.cfg.Window)
		if len(st.ports) == 0 && len(st.hosts) == 0 {
			delete(d.state, pid)
			continue
		}

		distinctPorts := len(st.ports)
		distinctHosts := len(st.hosts)
		knownScanner := d.scanners[strings.ToLower(st.comm)]

		if distinctPorts < d.cfg.DistinctPorts && distinctHosts < d.cfg.DistinctHosts && !knownScanner {
			continue
		}

		sev := core.SeverityMedium
		title := "Port scan detected"
		if knownScanner {
			sev = core.SeverityHigh
			title = "Network scanner running"
		}

		containerID := st.containerID
		if containerID == "" {
			containerID = system.ContainerIDForPID(pid)
		}
		ev := core.Event{
			Time:        now,
			Detector:    d.Name(),
			Category:    core.CategoryPortScan,
			Severity:    sev,
			Title:       title,
			PID:         pid,
			Process:     st.comm,
			ContainerID: containerID,
			Description: fmt.Sprintf("Process %q (pid %d) opened %d half-open connections across %d ports / %d hosts within %s.",
				st.comm, pid, distinctPorts+distinctHosts, distinctPorts, distinctHosts, d.cfg.Window),
		}
		ev.AddEvidence("distinct_ports", fmt.Sprintf("%d", distinctPorts))
		ev.AddEvidence("distinct_hosts", fmt.Sprintf("%d", distinctHosts))
		d.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}
	return events, nil
}

func prunePortState(st *scanState, now time.Time, window time.Duration) {
	for p, t := range st.ports {
		if now.Sub(t) > window {
			delete(st.ports, p)
		}
	}
	for h, t := range st.hosts {
		if now.Sub(t) > window {
			delete(st.hosts, h)
		}
	}
}
