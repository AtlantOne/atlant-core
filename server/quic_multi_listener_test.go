package main

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/wire"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Exercise the real listener lifecycle, admission, mutual proof and stream
// handler, not an echo substitute for the VPN server.
func TestIndependentQUICListenerIdentitiesAndShutdown(t *testing.T) {
	isolateUsers(t)
	key := bytes.Repeat([]byte{0x39}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	if err := usersStorage.AddUser("alice", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	// The process default is deliberately not wire7. Per-listener policies
	// must still work without replacing cfg or the process identity.
	cfg.WireVersion = 6
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type running struct {
		addr     net.Addr
		identity *ecdh.PrivateKey
		cancel   context.CancelFunc
		done     chan error
	}
	var listeners []running
	for range 2 {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		identity, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			socket.Close()
			t.Fatal(err)
		}
		settings := DefaultConfig()
		settings.WireVersion, settings.SNI = 7, "localhost"
		localCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- serveUDPVPNServer(localCtx, socket, settings, identity) }()
		listeners = append(listeners, running{socket.LocalAddr(), identity, stop, done})
		t.Cleanup(stop)
	}
	connect := func(server running, pinned *ecdh.PrivateKey) (quicpeer.ClientConn, error) {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { packet.Close() })
		attempt, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		conn, closer, err := quicpeer.DialClient(attempt, &quic.Transport{Conn: packet}, server.addr,
			&tls.Config{ServerName: "localhost"}, quicpeer.ClientConfig(), 7,
			quicpeer.DirectCredentials{User: "alice", Key: key, ServerPublicKey: pinned.PublicKey().Bytes()})
		if closer != nil {
			t.Cleanup(func() { closer.Close() })
		}
		if conn != nil {
			t.Cleanup(func() { conn.CloseWithError(0, "done") })
		}
		if err == nil {
			err = quicpeer.AuthenticateClient(attempt, conn, "alice", key)
		}
		return conn, err
	}
	ping := func(conn quicpeer.ClientConn) {
		t.Helper()
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		defer stream.CancelRead(0)
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x11, Destination: "speedtest:80"}, 32, 256); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, "PING listeners\n"); err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(stream).ReadString('\n')
		if err != nil || line != "PONG listeners\n" {
			t.Fatalf("stream reply %q: %v", line, err)
		}
	}
	first, err := connect(listeners[0], listeners[0].identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := connect(listeners[1], listeners[1].identity)
	if err != nil {
		t.Fatal(err)
	}
	ping(first)
	ping(second)
	if _, err := connect(listeners[1], listeners[0].identity); err == nil {
		t.Fatal("another inbound's pinned identity granted access")
	}
	listeners[0].cancel()
	select {
	case err := <-listeners[0].done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("listener shutdown: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("listener did not stop")
	}
	ping(second)
	listeners[1].cancel()
	select {
	case err := <-listeners[1].done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("second listener did not stop")
	}
}
