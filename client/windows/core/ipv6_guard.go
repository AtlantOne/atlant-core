package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

var ipv6GuardMu sync.Mutex
var ipv6GuardName string
var runIPv6Guard = func(script string) error {
	script = "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); " + script
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("IPv6 firewall: %w: %s", err, out)
	}
	return nil
}

func ipv6GuardInstallScript(name, program string) string {
	// Windows rejects IPv6 /0 in this filter. Two /1 prefixes cover exactly
	// the same space without broadening the block to IPv4.
	command := "$ErrorActionPreference='Stop'; New-NetFirewallRule -Name '" + strings.ReplaceAll(name, "'", "''") + "' -DisplayName 'Atlant IPv6 leak protection' -Direction Outbound -Action Block -RemoteAddress '::/1','8000::/1' -Profile Any -PolicyStore ActiveStore"
	if program != "" {
		command += " -Program '" + strings.ReplaceAll(program, "'", "''") + "'"
	}
	return command + " | Out-Null"
}

func installIPv6Guard() error {
	ipv6GuardMu.Lock()
	defer ipv6GuardMu.Unlock()
	if ipv6GuardName != "" {
		return nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := "Atlant-IPv6-" + hex.EncodeToString(nonce[:])
	// Use a unique owned rule; do not change other VPNs' firewall groups.
	if err := runIPv6Guard(ipv6GuardInstallScript(name, "")); err != nil {
		return err
	}
	ipv6GuardName = name
	return nil
}

func removeIPv6Guard() error {
	ipv6GuardMu.Lock()
	defer ipv6GuardMu.Unlock()
	if ipv6GuardName == "" {
		return nil
	}
	if err := runIPv6Guard("$ErrorActionPreference='Stop'; Remove-NetFirewallRule -Name '" + ipv6GuardName + "' -PolicyStore ActiveStore"); err != nil {
		return err
	}
	ipv6GuardName = ""
	return nil
}
