package detectors

import "testing"

func TestContainsWord(t *testing.T) {
	cases := []struct {
		s, token string
		want     bool
	}{
		{"-byteswappedclients", "byte", false}, // the real-world false positive we fixed
		{"java -jar byte.jar", "byte", true},
		{"./xmrig --coin monero", "xmrig", true},
		{"run hping3 -S target", "hping3", true},
		{"hping3x", "hping3", false},
		{"prefixhping3", "hping3", false},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := containsWord(c.s, c.token); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.s, c.token, got, c.want)
		}
	}
}
