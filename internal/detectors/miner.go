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

// MinerDetector finds cryptocurrency miners using three independent signals:
//  1. known miner binary/argument signatures
//  2. sustained high CPU usage
//  3. outbound connections to mining-pool ports
//
// Any single strong signal raises an event; combined signals escalate severity.
type MinerDetector struct {
	cfg      config.MinerConfig
	resolver *containerResolver

	procNames map[string]bool
	poolPorts map[int]bool

	// CPU sampling state, keyed by pid.
	samples map[int]cpuSample
}

type cpuSample struct {
	jiffies   uint64
	at        time.Time
	highSince time.Time // zero when not currently over threshold
}

// NewMinerDetector builds a miner detector from config.
func NewMinerDetector(cfg config.MinerConfig, d *docker.Client) *MinerDetector {
	names := make(map[string]bool, len(cfg.KnownProcesses))
	for _, n := range cfg.KnownProcesses {
		names[strings.ToLower(n)] = true
	}
	ports := make(map[int]bool, len(cfg.PoolPorts))
	for _, p := range cfg.PoolPorts {
		ports[p] = true
	}
	return &MinerDetector{
		cfg:       cfg,
		resolver:  newContainerResolver(d),
		procNames: names,
		poolPorts: ports,
		samples:   map[int]cpuSample{},
	}
}

func (m *MinerDetector) Name() string { return "miner" }

func (m *MinerDetector) Run(ctx context.Context) ([]core.Event, error) {
	procs, err := system.ListProcesses()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var events []core.Event
	seen := make(map[int]bool, len(procs))

	for _, p := range procs {
		seen[p.PID] = true

		nameHit := m.matchesSignature(p)
		cpuHigh, cpuPct := m.trackCPU(p, now)

		if !nameHit && !cpuHigh {
			continue
		}

		ev := core.Event{
			Time:        now,
			Detector:    m.Name(),
			Category:    core.CategoryMiner,
			PID:         p.PID,
			Process:     procDisplay(p),
			ContainerID: p.ContainerID,
		}
		ev.AddEvidence("cpu_percent", fmt.Sprintf("%.1f", cpuPct))
		ev.AddEvidence("exe", p.Exe)
		ev.AddEvidence("cmdline", truncate(p.Cmdline, 200))

		switch {
		case nameHit && cpuHigh:
			ev.Severity = core.SeverityCritical
			ev.Title = "Cryptocurrency miner running"
			ev.Description = fmt.Sprintf("Known miner %q is using %.0f%% CPU on %s.", procDisplay(p), cpuPct, ev.Target())
		case nameHit:
			ev.Severity = core.SeverityHigh
			ev.Title = "Known miner binary detected"
			ev.Description = fmt.Sprintf("Process %q matches a known miner signature.", procDisplay(p))
		default: // cpuHigh only
			ev.Severity = core.SeverityMedium
			ev.Title = "Sustained high CPU usage"
			ev.Description = fmt.Sprintf("Process %q sustained %.0f%% CPU for over %ds (possible unknown miner).", procDisplay(p), cpuPct, m.cfg.SustainedSeconds)
		}
		m.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}

	events = append(events, m.checkPoolConnections(ctx, now)...)

	m.gc(seen)
	return events, nil
}

// matchesSignature checks comm, exe basename and cmdline against known names.
func (m *MinerDetector) matchesSignature(p system.Process) bool {
	if m.procNames[strings.ToLower(p.Comm)] {
		return true
	}
	exeBase := strings.ToLower(baseName(p.Exe))
	if m.procNames[exeBase] {
		return true
	}
	cmd := strings.ToLower(p.Cmdline)
	for name := range m.procNames {
		if strings.Contains(cmd, name) {
			return true
		}
	}
	// Common miner argument fingerprints regardless of binary name.
	for _, sig := range []string{"--coin", "stratum+tcp", "stratum+ssl", "--donate-level", "randomx", "-o pool", "--algo"} {
		if strings.Contains(cmd, sig) {
			return true
		}
	}
	return false
}

// trackCPU computes a per-core CPU percentage from two samples and reports
// whether usage has stayed above the threshold for the configured window.
func (m *MinerDetector) trackCPU(p system.Process, now time.Time) (bool, float64) {
	cur := p.CPUJiffies()
	prev, ok := m.samples[p.PID]
	sample := cpuSample{jiffies: cur, at: now, highSince: prev.highSince}

	var pct float64
	if ok && now.After(prev.at) {
		elapsed := now.Sub(prev.at).Seconds()
		if elapsed > 0 && cur >= prev.jiffies {
			delta := float64(cur - prev.jiffies)
			pct = delta / (elapsed * system.ClockTicks) * 100
		}
	}

	high := false
	if pct >= m.cfg.CPUThreshold {
		if sample.highSince.IsZero() {
			sample.highSince = now
		}
		if now.Sub(sample.highSince) >= time.Duration(m.cfg.SustainedSeconds)*time.Second {
			high = true
		}
	} else {
		sample.highSince = time.Time{}
	}
	m.samples[p.PID] = sample
	return high, pct
}

// checkPoolConnections flags processes connected to known mining-pool ports.
func (m *MinerDetector) checkPoolConnections(ctx context.Context, now time.Time) []core.Event {
	conns, err := system.ReadConnections()
	if err != nil {
		return nil
	}
	var events []core.Event
	reported := map[int]bool{}
	for _, c := range conns {
		if !c.Established() || c.PID == 0 || reported[c.PID] {
			continue
		}
		if !m.poolPorts[c.RemotePort] {
			continue
		}
		reported[c.PID] = true
		ev := core.Event{
			Time:        now,
			Detector:    m.Name(),
			Category:    core.CategoryMiner,
			Severity:    core.SeverityHigh,
			Title:       "Connection to mining pool port",
			Description: fmt.Sprintf("Process %q (pid %d) is connected to %s:%d, a common mining-pool port.", c.Process, c.PID, c.RemoteIP, c.RemotePort),
			PID:         c.PID,
			Process:     c.Process,
			ContainerID: system.ContainerIDForPID(c.PID),
		}
		ev.AddEvidence("remote", fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort))
		m.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}
	return events
}

// gc drops CPU samples for pids that no longer exist to bound memory.
func (m *MinerDetector) gc(seen map[int]bool) {
	for pid := range m.samples {
		if !seen[pid] {
			delete(m.samples, pid)
		}
	}
}
