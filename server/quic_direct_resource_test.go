package main

import (
	"atlant.local/protocol/quicpeer"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func directFirstFragment(t *testing.T) []byte {
	t.Helper()
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, closer, _ := quicpeer.DialClient(ctx, &quic.Transport{Conn: socket}, sink.LocalAddr(), &tls.Config{ServerName: "localhost"}, quicpeer.ClientConfig(), 7, quicpeer.DirectCredentials{User: "alice", Key: key, ServerPublicKey: server.PublicKey().Bytes()})
		if conn != nil {
			conn.CloseWithError(0, "done")
		}
		if closer != nil {
			closer.Close()
		}
	}()
	defer func() { cancel(); <-done }()
	_ = sink.SetReadDeadline(time.Now().Add(time.Second))
	packet := make([]byte, 4096)
	n, _, err := sink.ReadFrom(packet)
	if err != nil {
		t.Fatal(err)
	}
	return packet[:n]
}

func TestDirectGateBoundsUnauthenticatedReassemblyAndExpires(t *testing.T) {
	packet := directFirstFragment(t)
	gate := newDirectQUICGate()
	for ip := 1; ip <= 16; ip++ {
		for port := 10000; port < 10064; port++ {
			addr := &net.UDPAddr{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", ip)), Port: port}
			_, accepted, held := gate.accept(packet, addr)
			if accepted || !held {
				t.Fatal("first fragment must wait")
			}
		}
	}
	gate.mu.Lock()
	count := len(gate.pending)
	gate.mu.Unlock()
	if count != directMaxPending {
		t.Fatal("unexpected global bound", count)
	}
	gate.accept(packet, &net.UDPAddr{IP: net.ParseIP("192.0.2.17"), Port: 10001})
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if len(gate.pending) != directMaxPending {
		t.Fatal("unbounded pending growth")
	}
	for _, p := range gate.pending {
		p.created = time.Now().Add(-11 * time.Second)
	}
	gate.lastSweep = time.Time{}
	gate.pruneLocked(time.Now())
	if len(gate.pending) != 0 || len(gate.perIP) != 0 {
		t.Fatal("expired entries retained")
	}
}
