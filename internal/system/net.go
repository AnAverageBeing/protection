package system

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TCP connection states as reported by /proc/net/tcp (hex).
const (
	tcpEstablished = "01"
	tcpSynSent     = "02"
)

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
// and matching "socket:[inode]" symlinks. This is the standard way to map a
// connection to its owning process without netlink.
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

	type owner struct {
		pid  int
		comm string
	}
	inodeOwner := make(map[uint64]owner)

	procs, _ := os.ReadDir("/proc")
	for _, e := range procs {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var comm string
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil || !want[inode] {
				continue
			}
			if comm == "" {
				comm = readComm(pid)
			}
			inodeOwner[inode] = owner{pid: pid, comm: comm}
		}
	}

	for i := range conns {
		if o, ok := inodeOwner[conns[i].Inode]; ok {
			conns[i].PID = o.pid
			conns[i].Process = o.comm
		}
	}
}

func readComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
