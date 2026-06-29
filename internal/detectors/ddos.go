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

// DDoSDetector spots outbound floods originating from containers or the host.
// Signals: per-container egress packet/byte rate (via docker stats), known
// stress-tool binaries, and abnormally high outbound connection counts.
type DDoSDetector struct {
	cfg      config.DDoSConfig
	docker   *docker.Client
	resolver *containerResolver
	tools    map[string]bool

	prev map[string]netSample // keyed by container id
}

type netSample struct {
	txPackets uint64
	txBytes   uint64
	at        time.Time
}

// NewDDoSDetector builds a DDoS detector from config.
func NewDDoSDetector(cfg config.DDoSConfig, d *docker.Client) *DDoSDetector {
	tools := make(map[string]bool, len(cfg.KnownTools))
	for _, t := range cfg.KnownTools {
		tools[strings.ToLower(t)] = true
	}
	return &DDoSDetector{
		cfg:      cfg,
		docker:   d,
		resolver: newContainerResolver(d),
		tools:    tools,
		prev:     map[string]netSample{},
	}
}

func (d *DDoSDetector) Name() string { return "ddos" }

func (d *DDoSDetector) Run(ctx context.Context) ([]core.Event, error) {
	now := time.Now()
	var events []core.Event

	events = append(events, d.checkContainerRates(ctx, now)...)
	events = append(events, d.checkToolSignatures(ctx, now)...)
	events = append(events, d.checkConnectionFloods(ctx, now)...)
	return events, nil
}

// checkContainerRates samples docker network stats and flags egress rates above
// the configured packet- or byte-per-second thresholds.
func (d *DDoSDetector) checkContainerRates(ctx context.Context, now time.Time) []core.Event {
	if d.docker == nil {
		return nil
	}
	containers, err := d.docker.ListContainers(ctx)
	if err != nil {
		return nil
	}
	var events []core.Event
	live := map[string]bool{}
	for _, c := range containers {
		live[c.ID] = true
		stats, err := d.docker.StatsOnce(ctx, c.ID)
		if err != nil {
			continue
		}
		var txp, txb uint64
		for _, n := range stats.Networks {
			txp += n.TxPackets
			txb += n.TxBytes
		}
		prev, ok := d.prev[c.ID]
		d.prev[c.ID] = netSample{txPackets: txp, txBytes: txb, at: now}
		if !ok {
			continue
		}
		elapsed := now.Sub(prev.at).Seconds()
		if elapsed <= 0 || txp < prev.txPackets {
			continue
		}
		pps := uint64(float64(txp-prev.txPackets) / elapsed)
		bps := uint64(float64(txb-prev.txBytes) / elapsed)

		if pps < d.cfg.PPSThreshold && bps < d.cfg.BPSThreshold {
			continue
		}
		ev := core.Event{
			Time:        now,
			Detector:    d.Name(),
			Category:    core.CategoryDDoS,
			Severity:    core.SeverityHigh,
			Title:       "Outbound flood from container",
			ContainerID: c.ID,
			Container:   c.Name(),
			Description: fmt.Sprintf("Container %s is emitting %s pps / %s — consistent with an outbound DDoS.", c.Name(), humanCount(pps), humanRate(bps)),
		}
		ev.AddEvidence("pps", fmt.Sprintf("%d", pps))
		ev.AddEvidence("bps", fmt.Sprintf("%d", bps))
		d.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}
	// drop stale containers
	for id := range d.prev {
		if !live[id] {
			delete(d.prev, id)
		}
	}
	return events
}

// checkToolSignatures matches running processes against known stress tools.
func (d *DDoSDetector) checkToolSignatures(ctx context.Context, now time.Time) []core.Event {
	procs, err := system.ListProcesses()
	if err != nil {
		return nil
	}
	var events []core.Event
	for _, p := range procs {
		cmd := strings.ToLower(p.Cmdline)
		hit := d.tools[strings.ToLower(p.Comm)] || d.tools[strings.ToLower(baseName(p.Exe))]
		if !hit {
			for tool := range d.tools {
				// word-boundary match so generic fragments (e.g. "byte" in
				// "-byteswappedclients") don't trigger false positives.
				if containsWord(cmd, tool) {
					hit = true
					break
				}
			}
		}
		// Java-hosted flooders ("java -jar ddos.jar") are common on game nodes.
		if !hit && strings.HasPrefix(p.Comm, "java") {
			for _, sig := range []string{"ddos", "booter", "stresser", "flood", "doser"} {
				if strings.Contains(cmd, sig) {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		ev := core.Event{
			Time:        now,
			Detector:    d.Name(),
			Category:    core.CategoryDDoS,
			Severity:    core.SeverityHigh,
			Title:       "DDoS / stress tool detected",
			PID:         p.PID,
			Process:     procDisplay(p),
			ContainerID: p.ContainerID,
			Description: fmt.Sprintf("Process %q matches a known DDoS/stress-tool signature.", procDisplay(p)),
		}
		ev.AddEvidence("cmdline", truncate(p.Cmdline, 200))
		d.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}
	return events
}

// checkConnectionFloods flags processes holding an abnormal number of
// simultaneous outbound connections.
func (d *DDoSDetector) checkConnectionFloods(ctx context.Context, now time.Time) []core.Event {
	conns, err := system.ReadConnections()
	if err != nil {
		return nil
	}
	count := map[int]int{}
	comm := map[int]string{}
	for _, c := range conns {
		if c.PID == 0 || (!c.Established() && !c.SynSent()) {
			continue
		}
		count[c.PID]++
		comm[c.PID] = c.Process
	}
	var events []core.Event
	for pid, n := range count {
		if n < d.cfg.ConnThreshold {
			continue
		}
		ev := core.Event{
			Time:        now,
			Detector:    d.Name(),
			Category:    core.CategoryDDoS,
			Severity:    core.SeverityHigh,
			Title:       "Connection flood",
			PID:         pid,
			Process:     comm[pid],
			ContainerID: system.ContainerIDForPID(pid),
			Description: fmt.Sprintf("Process %q (pid %d) holds %d simultaneous outbound connections.", comm[pid], pid, n),
		}
		ev.AddEvidence("connections", fmt.Sprintf("%d", n))
		d.resolver.resolve(ctx, &ev)
		events = append(events, ev)
	}
	return events
}

func humanCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func humanRate(bps uint64) string {
	bits := float64(bps) * 8
	switch {
	case bits >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", bits/1e9)
	case bits >= 1e6:
		return fmt.Sprintf("%.2f Mbit/s", bits/1e6)
	case bits >= 1e3:
		return fmt.Sprintf("%.2f Kbit/s", bits/1e3)
	default:
		return fmt.Sprintf("%.0f bit/s", bits)
	}
}
