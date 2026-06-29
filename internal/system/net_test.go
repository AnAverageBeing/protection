package system

import "testing"

func TestParseHexAddrIPv4(t *testing.T) {
	// /proc/net/tcp stores 127.0.0.1:80 in little-endian host order.
	ip, port := parseHexAddr("0100007F:0050")
	if got := ip.String(); got != "127.0.0.1" {
		t.Fatalf("ip = %q, want 127.0.0.1", got)
	}
	if port != 80 {
		t.Fatalf("port = %d, want 80", port)
	}
}

func TestParseHexAddrIPv6(t *testing.T) {
	// ::1 (loopback) on port 8080 (0x1F90).
	ip, port := parseHexAddr("00000000000000000000000001000000:1F90")
	if got := ip.String(); got != "::1" {
		t.Fatalf("ip = %q, want ::1", got)
	}
	if port != 8080 {
		t.Fatalf("port = %d, want 8080", port)
	}
}
