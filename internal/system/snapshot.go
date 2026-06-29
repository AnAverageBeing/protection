package system

import "time"

// Snapshot is a single coherent capture of system state shared by every
// detector on a scan tick. Gathering it once avoids each detector
// independently walking /proc and the socket table (which is the most
// expensive part of a scan), cutting per-tick syscall cost by ~4x.
type Snapshot struct {
	Time      time.Time
	Processes []Process
	Conns     []Conn
	CPUTotal  uint64
	NumCPU    int

	byPID map[int]*Process
}

// Gather captures processes (with CPU + I/O counters), TCP connections (with
// owning PIDs resolved) and global CPU totals.
func Gather() (*Snapshot, error) {
	procs, err := ListProcesses()
	if err != nil {
		return nil, err
	}
	// Gathers host + per-container connections, reusing the process list.
	conns := GatherConnections(procs)

	s := &Snapshot{
		Time:      time.Now(),
		Processes: procs,
		Conns:     conns,
		CPUTotal:  BootCPUTotal(),
		NumCPU:    NumCPU(),
		byPID:     make(map[int]*Process, len(procs)),
	}
	for i := range s.Processes {
		s.byPID[s.Processes[i].PID] = &s.Processes[i]
	}
	return s, nil
}

// Process returns the snapshot's process for a pid, or nil.
func (s *Snapshot) Process(pid int) *Process {
	if s == nil {
		return nil
	}
	return s.byPID[pid]
}
