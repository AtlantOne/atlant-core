package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestLinuxGuardRealPacketPaths(t *testing.T) {
	t.Run("IPv4-only", func(t *testing.T) { testLinuxGuardPacketPaths(t, false) })
	t.Run("dual-stack", func(t *testing.T) { testLinuxGuardPacketPaths(t, true) })
}

func testLinuxGuardPacketPaths(t *testing.T, dualStack bool) {
	path := os.Getenv("ATLANT_NFT_PROBE_SCRIPT")
	if path == "" {
		t.Skip("isolated namespace runner required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == parent {
		t.Fatal("refusing firewall test in the host network namespace")
	}
	script, err := linuxGuardScript("atlant_packet_probe", "atlant-test", "1.1.1.1")
	if dualStack {
		script, err = linuxGuardScriptForEndpoints("atlant_packet_probe", "atlant-test", "1.1.1.1", []string{"[2001:db8::1]:1026"}, "2606:4700:4700::1111")
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "unshare", "-n", "--", "python3", path)
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatalf("packet-path verification: %v", err)
	}
}
