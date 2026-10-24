package main

import (
	"strings"
	"testing"
)

func TestLinuxGuardBlocksExternalIPv6AndRedirectsDNS(t *testing.T) {
	script, err := linuxGuardScript("atlant_test", "atlant0", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, need := range []string{"meta nfproto ipv6", "udp dport 53 dnat ip to 1.1.1.1", "tcp dport 53 dnat ip to 1.1.1.1", "oifname != { \"lo\", \"atlant0\" }"} {
		if !strings.Contains(script, need) {
			t.Fatalf("missing guard %s", need)
		}
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("other VPN/firewall state must be preserved")
	}
	if !strings.Contains(script, "hook postrouting") || !strings.Contains(script, "meta iif 0") {
		t.Fatal("DNS egress must be checked after DNAT rerouting and only for local traffic")
	}
}

func TestLinuxGuardRejectsUnsafeDNS(t *testing.T) {
	for _, dns := range []string{"127.0.0.1", "192.168.1.1", "::1", "1.1.1.1\nflush ruleset"} {
		if _, err := linuxGuardScript("atlant_test", "atlant0", dns); err == nil {
			t.Fatal("unsafe DNS accepted")
		}
	}
}

func TestLinuxDualStackGuard(t *testing.T) {
	script, err := linuxGuardScript("atlant_test", "atlant0", "1.1.1.1", "2606:4700:4700::1111")
	if err != nil {
		t.Fatal(err)
	}
	for _, need := range []string{"dnat ip6 to 2606:4700:4700::1111", "meta nfproto ipv6 oifname != { \"lo\", \"atlant0\" } drop"} {
		if !strings.Contains(script, need) {
			t.Fatal("missing dual-stack protection", need)
		}
	}
	for _, bad := range []string{"::1", "fd00::1", "1.1.1.1", "2606::1\nflush ruleset"} {
		if _, err := linuxGuardScript("atlant_test", "atlant0", "1.1.1.1", bad); err == nil {
			t.Fatal("unsafe IPv6 DNS accepted")
		}
	}
}
