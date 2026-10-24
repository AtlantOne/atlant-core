package main

import (
	"errors"
	"strings"
	"testing"
)

func TestIPv6GuardOnlyRemovesOwnedRuntimeRule(t *testing.T) {
	old := runIPv6Guard
	oldName := ipv6GuardName
	t.Cleanup(func() { runIPv6Guard = old; ipv6GuardName = oldName })
	ipv6GuardName = ""
	var commands []string
	runIPv6Guard = func(s string) error { commands = append(commands, s); return nil }
	if err := installIPv6Guard(); err != nil {
		t.Fatal(err)
	}
	name := ipv6GuardName
	if err := installIPv6Guard(); err != nil {
		t.Fatal(err)
	}
	if err := removeIPv6Guard(); err != nil {
		t.Fatal(err)
	}
	if len(commands) != 2 || !strings.Contains(commands[0], "-PolicyStore ActiveStore") || !strings.Contains(commands[1], "-Name '"+name+"'") || strings.Contains(commands[1], "*") {
		t.Fatal("unscoped firewall mutation")
	}
}

func TestIPv6GuardFailureIsNotReportedAsProtected(t *testing.T) {
	old := runIPv6Guard
	oldName := ipv6GuardName
	t.Cleanup(func() { runIPv6Guard = old; ipv6GuardName = oldName })
	ipv6GuardName = ""
	runIPv6Guard = func(string) error { return errors.New("denied") }
	if installIPv6Guard() == nil || ipv6GuardName != "" {
		t.Fatal("failed firewall protection accepted")
	}
}

func TestIPv6GuardUsesSupportedCompleteIPv6Prefixes(t *testing.T) {
	s := ipv6GuardInstallScript("owned", "")
	if !strings.Contains(s, "-RemoteAddress '::/1','8000::/1'") || strings.Contains(s, "'::/0'") || strings.Contains(s, "-RemoteAddress Any") {
		t.Fatal("unsupported or incomplete IPv6 protection")
	}
}
