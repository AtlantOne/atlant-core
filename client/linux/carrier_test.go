package main

import "testing"

func TestLinuxCarrierPolicy(t *testing.T) {
	for _, tc := range []struct{ mode, carrier, tcp, udp, network, want string }{
		{"split", "reality", "xhttp", "quic", "udp", "quic"},
		{"split", "reality", "xhttp", "quic", "tcp", "xhttp"},
		{"tcp", "quic", "xhttp", "quic", "udp", "xhttp"},
		{"tcp", "reality", "reality", "quic", "udp", "reality"},
		{"udp", "reality", "reality", "tcp", "tcp", "quic"},
		{"split", "quic", "reality", "quic", "tcp", "quic"},
		{"split", "xhttp", "reality", "tcp", "udp", "xhttp"},
	} {
		cfg := &Config{TrafficMode: tc.mode, Transport: tc.carrier, TCPProto: tc.tcp, UDPProto: tc.udp}
		if got := linuxCarrier(cfg, tc.network); got != tc.want {
			t.Errorf("%+v: got %s", tc, got)
		}
	}
}
