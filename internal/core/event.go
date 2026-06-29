// Package core defines the shared data types used across the protection
// daemon: security events, severities and threat categories. Keeping these in
// a leaf package avoids import cycles between detectors, alerters and actions.
package core

import (
	"fmt"
	"strings"
	"time"
)

// Severity describes how dangerous a detected event is.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// ParseSeverity converts a human string into a Severity. Unknown values map to
// SeverityMedium so a typo in config never silently disables a rule.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium", "med":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical", "crit":
		return SeverityCritical
	default:
		return SeverityMedium
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Color returns a Discord-friendly decimal color for the severity.
func (s Severity) Color() int {
	switch s {
	case SeverityInfo:
		return 0x3498DB // blue
	case SeverityLow:
		return 0x2ECC71 // green
	case SeverityMedium:
		return 0xF1C40F // yellow
	case SeverityHigh:
		return 0xE67E22 // orange
	case SeverityCritical:
		return 0xE74C3C // red
	default:
		return 0x95A5A6
	}
}

// Category groups events by the kind of threat that produced them.
type Category string

const (
	CategoryMiner    Category = "miner"
	CategoryPortScan Category = "portscan"
	CategoryDDoS     Category = "ddos"
	CategoryZipBomb  Category = "zipbomb"
	CategoryExploit  Category = "exploit"
	CategoryAbuse    Category = "abuse"
	CategorySystem   Category = "system"
)

// Event is a single security finding produced by a detector. Fields are
// best-effort: a detector fills in whatever context it managed to gather.
type Event struct {
	Time        time.Time         `json:"time"`
	Detector    string            `json:"detector"`
	Category    Category          `json:"category"`
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	PID         int               `json:"pid,omitempty"`
	Process     string            `json:"process,omitempty"`
	User        string            `json:"user,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	Container   string            `json:"container,omitempty"`
	Server      string            `json:"server,omitempty"` // pterodactyl server uuid/id
	Path        string            `json:"path,omitempty"`   // file path if relevant
	Evidence    map[string]string `json:"evidence,omitempty"`
}

// Key returns a stable identifier used to de-duplicate repeated events within
// the engine's cooldown window. Two findings about the same threat on the same
// target collapse to one alert/action.
func (e Event) Key() string {
	target := e.ContainerID
	if target == "" {
		target = fmt.Sprintf("pid:%d", e.PID)
	}
	if e.Path != "" {
		target = e.Path
	}
	return fmt.Sprintf("%s|%s|%s", e.Category, e.Detector, target)
}

// Target returns the most specific human-readable subject of the event.
func (e Event) Target() string {
	switch {
	case e.Container != "":
		return fmt.Sprintf("container %s", e.Container)
	case e.ContainerID != "":
		return fmt.Sprintf("container %s", short(e.ContainerID))
	case e.Process != "":
		return fmt.Sprintf("process %s (pid %d)", e.Process, e.PID)
	case e.Path != "":
		return e.Path
	default:
		return "host"
	}
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// AddEvidence is a convenience helper that lazily initialises the map.
func (e *Event) AddEvidence(k, v string) {
	if e.Evidence == nil {
		e.Evidence = make(map[string]string)
	}
	e.Evidence[k] = v
}
