package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestMissingSOCKSBindDefaultsToLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"sni":"example.com","server":"127.0.0.1:443","pbk":"1111111111111111111111111111111111111111111111111111111111111111","user":"unit-test"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := loadConfigFromFile(path)
	if cfg == nil {
		t.Fatal("could not load defaults")
	}
	host, _, err := net.SplitHostPort(cfg.LocalPort)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("unsafe default SOCKS bind: %q", cfg.LocalPort)
	}
}

func TestAllowLANRequiredForAllNonLoopbackBinds(t *testing.T) {
	for _, address := range []string{":1080", "0.0.0.0:1080", "[::]:1080"} {
		got, err := socksBindAddress(address, false)
		if err != nil || got != "127.0.0.1:1080" {
			t.Fatalf("%s: got=%q err=%v", address, got, err)
		}
	}
	for _, address := range []string{"192.0.2.1:1080", "server.example:1080"} {
		if _, err := socksBindAddress(address, false); err == nil {
			t.Fatalf("LAN bind admitted without permission: %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080", "localhost:1080"} {
		if _, err := socksBindAddress(address, false); err != nil {
			t.Fatal(err)
		}
	}
	got, err := socksBindAddress(":1080", true)
	if err != nil || got != "0.0.0.0:1080" {
		t.Fatalf("explicit LAN bind: %q %v", got, err)
	}
}
