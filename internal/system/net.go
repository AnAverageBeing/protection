package system

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TCP connection states as reported by /proc/net/tcp (hex).
const (
	tcpEstablished = "01"
	tcpSynSent     = "02"
)

// pidResolveBudget caps how long socket→pid resolution may take per scan, so a
// pathological process with a huge fd table can't stall the detection loop.
const pidResolveBudget = 1500 * time.Millisecond

// Conn is one row from /proc/net/tcp{,6}.
type Conn struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string
	Inode      uint64
	PID        int    // resolved lazily via inode→fd mapping
	Process    string // comm of owning pid
}

// Established reports whether the connection is in the ESTABLISHED state.
func (c Conn) Established() bool { return c.State == tcpEstablished }

// SynSent reports whether the connection is mid-handshake (typical of scans).
func (c Conn) SynSent() bool { return c.State == tcpSynSent }

// ReadConnections parses both IPv4 and IPv6 TCP tables and attaches owning PIDs.
func ReadConnections() ([]Conn, error) {
	var conns []Conn
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		c, err := parseProcNetTCP(path)
		if err != nil {
			continue // tcp6 may be absent on IPv4-only hosts
		}
		conns = append(conns, c...)
	}
	attachPIDs(conns)
	return conns, nil
}

func parseProcNetTCP(path string) ([]Conn, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	var conns []Conn
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		lip, lport := parseHexAddr(fields[1])
		rip, rport := parseHexAddr(fields[2])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)
		conns = append(conns, Conn{
			LocalIP:    lip,
			LocalPort:  lport,
			RemoteIP:   rip,
			RemotePort: rport,
			State:      fields[3],
			Inode:      inode,
		})
	}
	return conns, nil
}

// parseHexAddr decodes the "IP:PORT" hex form used in /proc/net/tcp. IPv4 is
// 8 hex chars (little-endian), IPv6 is 32 hex chars.
func parseHexAddr(s string) (net.IP, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)

	raw := parts[0]
	switch len(raw) {
	case 8: // IPv4
		b, err := hexToBytes(raw)
		if err != nil || len(b) != 4 {
			return nil, int(port)
		}
		// /proc stores the address in host (little-endian) byte order.
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return ip, int(port)
	case 32: // IPv6
		b, err := hexToBytes(raw)
		if err != nil || len(b) != 16 {
			return nil, int(port)
		}
		ip := make(net.IP, 16)
		// Each 4-byte word is little-endian.
		for i := 0; i < 16; i += 4 {
			word := binary.LittleEndian.Uint32(b[i : i+4])
			binary.BigEndian.PutUint32(ip[i:i+4], word)
		}
		return ip, int(port)
	default:
		return nil, int(port)
	}
}

func hexToBytes(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// attachPIDs builds an inode→pid map by walking every process's fd directory
// and matching "socket:[inode]" symlinks — the standard way to map a connection
// to its owning process without netlink.
//
// On busy hosts there can be hundreds of thousands of open fds, and each needs
// a readlink syscall, so we fan the per-process walk out across a worker pool.
// This turns a multi-second serial scan into a sub-second parallel one.
func attachPIDs(conns []Conn) {
	if len(conns) == 0 {
		return
	}
	want := make(map[uint64]bool, len(conns))
	for _, c := range conns {
		if c.Inode != 0 {
			want[c.Inode] = true
		}
	}

	type match struct {
		inode uint64
		pid   int
	}

	// Collect candidate pids first.
	entries, _ := os.ReadDir("/proc")
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}

	workers := runtime.NumCPU() * 4
	if workers < 4 {
		workers = 4
	}
	if workers > 64 {
		workers = 64
	}

	// A job is a slice of fd paths belonging to one pid. We chunk each process's
	// fds so that a single process with an enormous fd table (a leak, or an
	// abuser deliberately holding many sockets) is still split across all
	// workers instead of pinning one of them.
	type job struct {
		pid   int
		fdDir string
		names []string
	}
	const chunk = 2048

	jobs := make(chan job, workers*2)
	var mu sync.Mutex
	inodePID := make(map[uint64]int)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []match
			for j := range jobs {
				for _, name := range j.names {
					link, err := os.Readlink(filepath.Join(j.fdDir, name))
					if err != nil || !strings.HasPrefix(link, "socket:[") {
						continue
					}
					inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
					inode, err := strconv.ParseUint(inodeStr, 10, 64)
					if err != nil || !want[inode] {
						continue
					}
					local = append(local, match{inode: inode, pid: j.pid})
				}
			}
			if len(local) > 0 {
				mu.Lock()
				for _, m := range local {
					inodePID[m.inode] = m.pid
				}
				mu.Unlock()
			}
		}()
	}

	// Bound total resolution time. On a healthy node this never triggers (the
	// scan finishes in milliseconds); on a host with a pathological
	// socket-leaking process it prevents one bad neighbour from stalling every
	// tick. Connections left unresolved simply have PID==0 and are skipped by
	// pid-level checks (container-level checks are unaffected).
	deadline := time.Now().Add(pidResolveBudget)
	go func() {
		defer close(jobs)
		for _, pid := range pids {
			if time.Now().After(deadline) {
				return
			}
			fdDir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
			ents, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			names := make([]string, len(ents))
			for i, e := range ents {
				names[i] = e.Name()
			}
			for i := 0; i < len(names); i += chunk {
				end := i + chunk
				if end > len(names) {
					end = len(names)
				}
				jobs <- job{pid: pid, fdDir: fdDir, names: names[i:end]}
			}
		}
	}()
	wg.Wait()

	// Resolve comm once per owning pid (cheap: at most one per connection).
	commCache := make(map[int]string)
	for i := range conns {
		pid, ok := inodePID[conns[i].Inode]
		if !ok {
			continue
		}
		comm, seen := commCache[pid]
		if !seen {
			comm = readComm(pid)
			commCache[pid] = comm
		}
		conns[i].PID = pid
		conns[i].Process = comm
	}
}

func readComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
