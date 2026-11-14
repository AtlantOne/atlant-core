package main

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestIdleChaffingDoesNotDialServer(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := &Config{ServerAddr: listener.Addr().String(), Mux: true, ChaffingEnabled: true, ChaffingInterval: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		startChaffingWorker(ctx, cfg)
	}()
	defer func() { cancel(); <-done }()
	// The first optional pulse is due no later than 1.35 seconds.
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err == nil {
		_ = conn.Close()
		t.Fatal("idle VPN opened a TCP connection for background traffic")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestChaffingLinkRequiresExplicitOptIn(t *testing.T) {
	const link = "atlant://example.test:443?sni=example.test&pbk=test&user=test"
	for query, enabled := range map[string]bool{"": false, "&chaffing=false": false, "&chaffing=true": true} {
		cfg := parseAtlantURL(link + query)
		if cfg == nil || cfg.ChaffingEnabled != enabled {
			t.Fatalf("unexpected chaffing policy for %q", query)
		}
	}
}
