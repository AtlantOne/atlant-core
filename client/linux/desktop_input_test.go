package main

import (
	"strings"
	"testing"
)

func TestDesktopInputPreservesAliasesAndShutdownFrame(t *testing.T) {
	cfg := &Config{TunName: "atlant0", TunAddr: "10.254.1.2/24"}
	scanner, err := readDesktopInput(strings.NewReader("{\"server\":\"127.0.0.1:1026\",\"dns\":\"1.1.1.1\",\"block_ipv6\":true,\"pbk\":\"private-test-key\",\"quic_fingerprint\":\"chrome_146\",\"tun\":true}\nSTOP\n"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != "127.0.0.1:1026" || cfg.PBK != "private-test-key" || cfg.TunDNS != "1.1.1.1" || !cfg.DisableIPv6 || !cfg.Tun || cfg.TunName != "atlant0" || cfg.QUICFingerprint != "chrome_146" {
		t.Fatal("desktop configuration changed or defaults lost")
	}
	if !scanner.Scan() || scanner.Text() != "STOP" {
		t.Fatal("shutdown frame consumed while reading configuration")
	}
}
func TestDesktopInputRejectsUnsupportedProtectionAndOversizedFrames(t *testing.T) {
	for _, input := range []string{"{\"kill_switch\":true}\n", "{\"route_mode\":\"proxy_apps\"}\n", "not-json\n", strings.Repeat("x", (4<<20)+1) + "\n"} {
		if _, err := readDesktopInput(strings.NewReader(input), &Config{}); err == nil {
			t.Fatal("invalid or unsupported configuration accepted")
		}
	}
}

func TestDesktopInputPreservesAggregateBandwidthAndPool(t *testing.T) {
	cfg := &Config{}
	if _, err := readDesktopInput(strings.NewReader("{\"up_mbps\":5,\"down_mbps\":20,\"quic_parallel_connections\":3}\nSTOP\n"), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.UpMbps != 5 || cfg.DownMbps != 20 || cfg.QUICParallelConnections != 3 {
		t.Fatal("bandwidth or pool settings lost")
	}
}
