package atlant

import "testing"

func TestDNSUsesSelectedQUICCarrier(t *testing.T) {
	for _, test := range []struct {
		tcp, udp      string
		blocked, want bool
	}{
		{"quic", "quic", false, true}, {"udp", "quic", false, true},
		{"tcp", "quic", false, false}, {"xhttp", "quic", false, false},
		{"quic", "tcp", false, false}, {"quic", "quic", true, false},
	} {
		if got := dnsViaQUIC(test.tcp, test.udp, test.blocked); got != test.want {
			t.Errorf("DNS transport policy: %+v got %v", test, got)
		}
	}
}
