// Package engine is the orchestrator: it drives detectors on a schedule,
// de-duplicates findings, matches them against the rule set, then fans out to
// alert channels and enforcement actions.
package engine

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"protection/internal/actions"
	"protection/internal/alerts"
	"protection/internal/config"
	"protection/internal/core"
	"protection/internal/detectors"
	"protection/internal/logging"
)

// Engine coordinates detection, alerting and enforcement.
type Engine struct {
	cfg       *config.Config
	detectors []detectors.Detector
	alerters  []alerts.Alerter
	actions   *actions.Registry

	mu       sync.Mutex
	lastSeen map[string]time.Time // event key → last handled, for cooldown
}

// New constructs an Engine.
func New(cfg *config.Config, dets []detectors.Detector, alerters []alerts.Alerter, reg *actions.Registry) *Engine {
	return &Engine{
		cfg:       cfg,
		detectors: dets,
		alerters:  alerters,
		actions:   reg,
		lastSeen:  map[string]time.Time{},
	}
}

// Run drives the detection loop until the context is cancelled.
func (e *Engine) Run(ctx context.Context) {
	logging.Info("protection engine started: %d detectors, %d alert channels, interval=%s, dry_run=%v",
		len(e.detectors), len(e.alerters), e.cfg.General.ScanInterval, e.cfg.General.DryRun)

	ticker := time.NewTicker(e.cfg.General.ScanInterval)
	defer ticker.Stop()

	// First pass establishes CPU/network baselines; do it immediately.
	e.scan(ctx)
	for {
		select {
		case <-ctx.Done():
			logging.Info("protection engine stopping")
			return
		case <-ticker.C:
			e.scan(ctx)
		}
	}
}

// ScanOnce runs every detector a single time and returns the findings without
// taking action. Used by the `scan` CLI command.
func (e *Engine) ScanOnce(ctx context.Context) []core.Event {
	var all []core.Event
	for _, d := range e.detectors {
		evs, err := d.Run(ctx)
		if err != nil {
			logging.Warn("detector %s error: %v", d.Name(), err)
			continue
		}
		all = append(all, evs...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Severity > all[j].Severity })
	return all
}

func (e *Engine) scan(ctx context.Context) {
	for _, d := range e.detectors {
		evs, err := d.Run(ctx)
		if err != nil {
			logging.Warn("detector %s error: %v", d.Name(), err)
			continue
		}
		for _, ev := range evs {
			e.handle(ctx, ev)
		}
	}
}

// handle applies cooldown, rule matching, alerting and enforcement to one event.
func (e *Engine) handle(ctx context.Context, ev core.Event) {
	if e.inCooldown(ev) {
		logging.Debug("suppressing duplicate event %s (cooldown)", ev.Key())
		return
	}

	logging.Warn("[%s] %s — %s", strings.ToUpper(ev.Severity.String()), ev.Title, ev.Description)

	actionSet := e.matchActions(ev)
	if len(actionSet) == 0 {
		return
	}

	if actionSet["alert"] {
		e.dispatchAlerts(ctx, ev)
	}
	for name := range actionSet {
		if name == "alert" || name == "log_only" {
			continue
		}
		if err := e.actions.Run(ctx, name, ev); err != nil {
			logging.Error("action %q failed on %s: %v", name, ev.Target(), err)
		}
	}
}

// matchActions returns the union of actions from every rule that matches the
// event's category and severity.
func (e *Engine) matchActions(ev core.Event) map[string]bool {
	set := map[string]bool{}
	for _, r := range e.cfg.Rules {
		if !ruleMatches(r, ev) {
			continue
		}
		for _, a := range r.Actions {
			set[a] = true
		}
	}
	return set
}

func ruleMatches(r config.Rule, ev core.Event) bool {
	if ev.Severity < core.ParseSeverity(r.MinSeverity) {
		return false
	}
	for _, c := range r.Categories {
		if c == "*" || c == string(ev.Category) {
			return true
		}
	}
	return false
}

func (e *Engine) dispatchAlerts(ctx context.Context, ev core.Event) {
	for _, a := range e.alerters {
		if ev.Severity < a.MinSeverity() {
			continue
		}
		a := a
		go func() {
			actx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			if err := a.Send(actx, ev); err != nil {
				logging.Error("alert channel %q failed: %v", a.Name(), err)
			} else {
				logging.Debug("alert sent via %s for %s", a.Name(), ev.Key())
			}
		}()
	}
}

func (e *Engine) inCooldown(ev core.Event) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := ev.Key()
	if last, ok := e.lastSeen[key]; ok && time.Since(last) < e.cfg.General.Cooldown {
		return true
	}
	e.lastSeen[key] = time.Now()
	// opportunistic GC of expired keys
	for k, t := range e.lastSeen {
		if time.Since(t) > 2*e.cfg.General.Cooldown {
			delete(e.lastSeen, k)
		}
	}
	return false
}
