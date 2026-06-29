// Package system contains low-level Linux introspection helpers built on /proc.
// Everything here is pure Go (no cgo) so the daemon stays a single static
// binary that can be dropped onto any node.
package system

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Process is a snapshot of a running process gathered from /proc.
type Process struct {
	PID         int
	Comm        string // executable name (from /proc/pid/stat, truncated to 15 chars)
	Cmdline     string // full command line, NUL-joined into spaces
	Exe         string // resolved /proc/pid/exe target
	UID         int
	ContainerID string // docker/containerd id if the process lives in a container
	UTime       uint64 // user jiffies
	STime       uint64 // kernel jiffies
	StartTime   uint64 // jiffies since boot
	State       string
}

// CPUJiffies returns the total CPU time consumed by the process in jiffies.
func (p Process) CPUJiffies() uint64 { return p.UTime + p.STime }

var containerIDRe = regexp.MustCompile(`([0-9a-f]{64})`)

// ListProcesses enumerates every process visible in /proc.
func ListProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var procs []Process
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid directory
		}
		p, err := ReadProcess(pid)
		if err != nil {
			continue // process may have exited; skip quietly
		}
		procs = append(procs, p)
	}
	return procs, nil
}

// ReadProcess gathers a single process snapshot. Missing fields are tolerated.
func ReadProcess(pid int) (Process, error) {
	p := Process{PID: pid}
	base := filepath.Join("/proc", strconv.Itoa(pid))

	if err := p.readStat(base); err != nil {
		return p, err
	}
	p.Cmdline = readCmdline(filepath.Join(base, "cmdline"))
	if target, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		p.Exe = target
	}
	p.UID = readUID(filepath.Join(base, "status"))
	p.ContainerID = readContainerID(filepath.Join(base, "cgroup"))
	return p, nil
}

func (p *Process) readStat(base string) error {
	data, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return err
	}
	s := string(data)
	// comm is wrapped in parens and may itself contain spaces/parens, so we
	// anchor on the last ')' before parsing the space-separated remainder.
	open := strings.IndexByte(s, '(')
	closeIdx := strings.LastIndexByte(s, ')')
	if open >= 0 && closeIdx > open {
		p.Comm = s[open+1 : closeIdx]
		s = s[closeIdx+1:]
	}
	fields := strings.Fields(s)
	// After comm, field[0] is state. utime=field[11], stime=field[12],
	// starttime=field[19] (0-indexed within this trimmed slice).
	if len(fields) > 0 {
		p.State = fields[0]
	}
	if len(fields) > 12 {
		p.UTime, _ = strconv.ParseUint(fields[11], 10, 64)
		p.STime, _ = strconv.ParseUint(fields[12], 10, 64)
	}
	if len(fields) > 19 {
		p.StartTime, _ = strconv.ParseUint(fields[19], 10, 64)
	}
	return nil
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	parts := strings.Split(string(data), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

func readUID(statusPath string) int {
	f, err := os.Open(statusPath)
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if uid, err := strconv.Atoi(fields[1]); err == nil {
					return uid
				}
			}
		}
	}
	return -1
}

// readContainerID extracts a 64-hex container id from a /proc/pid/cgroup file.
// Works for both cgroup v1 and v2 layouts and for docker/containerd/k8s.
func readContainerID(cgroupPath string) string {
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}
	if m := containerIDRe.FindString(string(data)); m != "" {
		return m
	}
	return ""
}

// SelfCgroupContainerID returns the container id of an arbitrary pid; "" if the
// process is on the host. Thin wrapper for callers that already know the pid.
func ContainerIDForPID(pid int) string {
	return readContainerID(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
}

// BootCPUTotal returns the total CPU jiffies across all cores from /proc/stat,
// used to convert per-process jiffies into a CPU percentage.
func BootCPUTotal() uint64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			var total uint64
			for _, f := range strings.Fields(line)[1:] {
				v, _ := strconv.ParseUint(f, 10, 64)
				total += v
			}
			return total
		}
	}
	return 0
}

// NumCPU returns the number of CPUs the kernel reports (cpu0, cpu1, ...).
func NumCPU() int {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 1
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu") && len(line) > 3 && line[3] != ' ' {
			n++
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

// ClockTicks is the kernel USER_HZ. It is effectively always 100 on Linux; we
// hardcode it to avoid a cgo sysconf call.
const ClockTicks = 100
