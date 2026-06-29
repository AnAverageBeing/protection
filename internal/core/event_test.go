package core

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"info":     SeverityInfo,
		"LOW":      SeverityLow,
		" medium ": SeverityMedium,
		"high":     SeverityHigh,
		"critical": SeverityCritical,
		"garbage":  SeverityMedium, // unknown defaults to medium, never disables a rule
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestEventKeyStability(t *testing.T) {
	a := Event{Category: CategoryMiner, Detector: "miner", ContainerID: "abc"}
	b := Event{Category: CategoryMiner, Detector: "miner", ContainerID: "abc", PID: 5}
	if a.Key() != b.Key() {
		t.Fatalf("events on the same container should share a key: %q vs %q", a.Key(), b.Key())
	}
	c := Event{Category: CategoryMiner, Detector: "miner", ContainerID: "xyz"}
	if a.Key() == c.Key() {
		t.Fatal("events on different containers must not share a key")
	}
}
