package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireTunNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("ATLANT_TUN_NAMESPACE_TEST") != "1" {
		t.Skip("run with the isolated Linux TUN namespace runner")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == host {
		t.Fatal("refusing TUN changes in host network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated TUN tests require root")
	}
}

func tunCommand(t *testing.T, command string, args ...string) string {
	t.Helper()
	out, err := exec.Command(command, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", command, args, err, out)
	}
	return string(out)
}

func tunFixture(t *testing.T) *Config {
	t.Helper()
	requireTunNamespace(t)
	tunCommand(t, "ip", "link", "set", "lo", "up")
	tunCommand(t, "ip", "link", "add", "tun-test-wan", "type", "dummy")
	t.Cleanup(func() { tunCommand(t, "ip", "link", "del", "tun-test-wan") })
	tunCommand(t, "ip", "addr", "add", "192.0.2.2/24", "dev", "tun-test-wan")
	tunCommand(t, "ip", "link", "set", "tun-test-wan", "up")
	tunCommand(t, "ip", "route", "add", "default", "via", "192.0.2.1", "dev", "tun-test-wan")
	return &Config{ServerAddr: "192.0.2.1:1026", TunName: "atlant-probe", TunAddr: "10.254.1.2/24", TunDNS: "1.1.1.1", MTU: 1380, FakeDNS: true}
}

func TestTunNamespaceDNSLifecycle(t *testing.T) {
	cfg := tunFixture(t)
	beforeRoutes := tunCommand(t, "ip", "-4", "route", "show")
	beforeRoutes6 := tunCommand(t, "ip", "-6", "route", "show")
	// An unrelated firewall table must survive both successful and failed startup.
	tunCommand(t, "nft", "add", "table", "inet", "tun_test_existing")
	t.Cleanup(func() { tunCommand(t, "nft", "delete", "table", "inet", "tun_test_existing") })
	beforeTables := tunCommand(t, "nft", "list", "tables")
	for cycle := 0; cycle < 3; cycle++ {
		ctx, cancel := context.WithCancel(context.Background())
		ready, done := make(chan struct{}), make(chan error, 1)
		go func() { done <- startTun(ctx, cfg, func() { close(ready) }) }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("TUN shutdown did not complete")
			}
		}
		defer stop()
		select {
		case <-ready:
		case err := <-done:
			stopped = true
			cancel()
			t.Fatalf("TUN startup: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("TUN readiness timeout")
		}
		if route := tunCommand(t, "ip", "route", "get", "8.8.8.8"); !strings.Contains(route, "dev "+cfg.TunName) {
			t.Fatal("external route bypasses TUN", route)
		}
		if route := tunCommand(t, "ip", "-6", "route", "get", "2001:4860:4860::8888"); !strings.Contains(route, "dev "+cfg.TunName) {
			t.Fatal("IPv6 bypasses TUN", route)
		}
		if route := tunCommand(t, "ip", "route", "get", "192.0.2.1"); !strings.Contains(route, "dev tun-test-wan") {
			t.Fatal("VPN endpoint loops into TUN", route)
		}
		link := tunCommand(t, "ip", "-o", "link", "show", cfg.TunName)
		if !strings.Contains(link, "mtu 1380") {
			t.Fatal("configured MTU was not applied", link)
		}
		for queryID := 1; queryID <= 32; queryID++ {
			// LAN and public DNS destinations must both enter the real TUN.
			target := "8.8.8.8:53"
			if queryID%2 == 0 {
				target = "192.0.2.1:53"
			}
			network := "udp4"
			if queryID%3 == 0 {
				network = "udp6"
				target = "[2001:db8:1::53]:53"
			}
			conn, err := net.DialTimeout(network, target, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			binary.BigEndian.PutUint16(query, uint16(queryID))
			_, err = conn.Write(query)
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			buffer := make([]byte, 2048)
			n, err := conn.Read(buffer)
			conn.Close()
			if err != nil {
				t.Fatalf("cycle %d query %d (%s): %v", cycle, queryID, target, err)
			}
			if n < 16 || binary.BigEndian.Uint16(buffer) != uint16(queryID) || buffer[2]&0x80 == 0 || binary.BigEndian.Uint16(buffer[6:8]) != 1 {
				t.Fatal("invalid DNS reply through TUN")
			}
			if !GetFakeDNS().IsFakeIP(net.IP(buffer[n-4 : n]).String()) {
				t.Fatal("unexpected DNS answer")
			}
		}
		stop()
		if out := tunCommand(t, "ip", "-4", "route", "show"); out != beforeRoutes {
			t.Fatalf("routes not restored\nbefore: %s\nafter: %s", beforeRoutes, out)
		}
		if out := tunCommand(t, "ip", "-6", "route", "show"); out != beforeRoutes6 {
			t.Fatalf("IPv6 routes not restored: %s", out)
		}
		if out := tunCommand(t, "nft", "list", "tables"); out != beforeTables {
			t.Fatalf("firewall tables not restored: %s", out)
		}
		if err := exec.Command("ip", "link", "show", cfg.TunName).Run(); err == nil {
			t.Fatal("TUN interface survived shutdown")
		}
		t.Logf("cycle %d: real TUN + 32 DNS packet round trips + MTU + endpoint bypass + exact cleanup PASS", cycle+1)
	}
}

func TestTunNamespaceRouteFailureRollsBack(t *testing.T) {
	cfg := tunFixture(t)
	tunCommand(t, "ip", "route", "add", "0.0.0.0/1", "dev", "tun-test-wan")
	beforeRoutes := tunCommand(t, "ip", "-4", "route", "show")
	beforeTables := tunCommand(t, "nft", "list", "tables")
	err := startTun(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "refusing unprotected startup") {
		t.Fatal("expected fail-closed route failure", err)
	}
	if out := tunCommand(t, "ip", "-4", "route", "show"); out != beforeRoutes {
		t.Fatal("failed startup changed existing routes", out)
	}
	if out := tunCommand(t, "nft", "list", "tables"); out != beforeTables {
		t.Fatal("failed startup left firewall rules", out)
	}
	if err := exec.Command("ip", "link", "show", cfg.TunName).Run(); err == nil {
		t.Fatal("failed startup left an interface")
	}
	t.Log(fmt.Sprintf("PASS: route conflict fails closed and removes only owned state"))
}
