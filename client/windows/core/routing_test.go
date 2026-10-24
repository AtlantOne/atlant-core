package main

import (
	"strings"
	"testing"
)

func TestDefaultRouteRequiresActiveIPv4InterfaceColumn(t *testing.T) {
	for _, tc := range []struct {
		row  string
		want bool
	}{
		{"0.0.0.0 0.0.0.0 192.168.0.1 192.168.0.202 35", true},
		{"0.0.0.0 0.0.0.0 172.18.0.2 172.18.0.1 0", true},
		{"0.0.0.0 0.0.0.0 10.254.1.1 1", false},
		{"0.0.0.0 0.0.0.0 10.254.1.1 1 999", false},
		{"0.0.0.0 0.0.0.0 On-link 192.168.0.202 35", false},
		{"0.0.0.0 0.0.0.0 192.168.0.1 192.168.0.202 bad", false},
		{"128.0.0.0 128.0.0.0 192.168.0.1 192.168.0.202 35", false},
	} {
		if got := validDefaultRouteFields(strings.Fields(tc.row)); got != tc.want {
			t.Errorf("%q: got %v, want %v", tc.row, got, tc.want)
		}
	}
}
