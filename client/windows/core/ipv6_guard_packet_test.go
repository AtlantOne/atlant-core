package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"
)

// Run only in the operator's isolated Windows VM with an external IPv6 test
// listener. The rule is additionally scoped to this test EXE, never the host.
func TestWindowsIPv6GuardRealPacketPath(t *testing.T) {
	if os.Getenv("ATLANT_WINDOWS_GUARD_ISOLATED") != "1" {
		t.Skip("requires isolated privileged Windows IPv6 fixture")
	}
	target := os.Getenv("ATLANT_WINDOWS_IPV6_TARGET")
	host, _, err := net.SplitHostPort(target)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		t.Fatal("explicit external IPv6 fixture IP:port required")
	}
	dial := func() error {
		c, err := net.DialTimeout("tcp6", target, 2*time.Second)
		if c != nil {
			c.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		t.Fatalf("baseline IPv6 fixture is unreachable: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	name := "Atlant-Test-IPv6-" + hex.EncodeToString(nonce[:])
	if err := runIPv6Guard(ipv6GuardInstallScript(name, exe)); err != nil {
		t.Fatalf("cannot install scoped test rule (admin required): %v", err)
	}
	cleanup := func() error {
		return runIPv6Guard("$ErrorActionPreference='Stop'; Remove-NetFirewallRule -Name '" + name + "' -PolicyStore ActiveStore")
	}
	removed := false
	defer func() {
		if !removed {
			if err := cleanup(); err != nil {
				t.Errorf("remove owned test rule %s: %v", name, err)
			}
		}
	}()
	if err := dial(); err == nil {
		t.Fatal("IPv6 connection escaped the guard")
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	removed = true
	if err := dial(); err != nil {
		t.Fatalf("IPv6 fixture did not recover after rule removal: %v", err)
	}
}
