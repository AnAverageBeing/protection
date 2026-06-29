package detectors

import (
	"path/filepath"
	"strings"

	"protection/internal/system"
)

// procDisplay returns the most descriptive name available for a process.
func procDisplay(p system.Process) string {
	if p.Comm != "" {
		return p.Comm
	}
	if p.Exe != "" {
		return baseName(p.Exe)
	}
	if p.Cmdline != "" {
		return strings.Fields(p.Cmdline)[0]
	}
	return "?"
}

func baseName(path string) string {
	if path == "" {
		return ""
	}
	// strip the " (deleted)" suffix the kernel appends to unlinked exes — a
	// classic malware tell where the binary deletes itself after launch.
	path = strings.TrimSuffix(path, " (deleted)")
	return filepath.Base(path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// inContainer reports whether a process belongs to a container.
func inContainer(containerID string) bool { return containerID != "" }

// containsWord reports whether token appears in s delimited by non-alphanumeric
// boundaries. This avoids false positives like "byte" matching
// "-byteswappedclients" while still catching "./byte" or "byte.jar".
func containsWord(s, token string) bool {
	if token == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(s[from:], token)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(token)
		if !isWordByte(s, start-1) && !isWordByte(s, end) {
			return true
		}
		from = start + 1
	}
}

func isWordByte(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	c := s[i]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
