// Package alerts delivers security events to notification channels (Discord,
// email, generic webhooks). Each channel honours its own minimum-severity gate.
package alerts

import (
	"context"

	"protection/internal/core"
)

// Alerter delivers a single event to a notification channel.
type Alerter interface {
	Name() string
	// Send delivers the event. It should return quickly; callers run it in a
	// goroutine with a timeout.
	Send(ctx context.Context, ev core.Event) error
	// MinSeverity is the lowest severity this channel cares about.
	MinSeverity() core.Severity
}

// fieldsFor builds the common ordered key/value pairs describing an event,
// reused by every channel's formatter.
func fieldsFor(ev core.Event, hostname string) [][2]string {
	fields := [][2]string{
		{"Severity", ev.Severity.String()},
		{"Category", string(ev.Category)},
		{"Detector", ev.Detector},
		{"Host", hostname},
	}
	if t := ev.Target(); t != "" {
		fields = append(fields, [2]string{"Target", t})
	}
	if ev.Container != "" {
		fields = append(fields, [2]string{"Container", ev.Container})
	}
	if ev.Server != "" {
		fields = append(fields, [2]string{"Server", ev.Server})
	}
	if ev.Process != "" {
		fields = append(fields, [2]string{"Process", ev.Process})
	}
	if ev.Path != "" {
		fields = append(fields, [2]string{"Path", ev.Path})
	}
	return fields
}
