package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type tcpShutdownListener struct {
	net.Listener
	readStarted chan struct{}
}

type tcpShutdownConn struct {
	net.Conn
	readStarted chan struct{}
	once        sync.Once
}

func (c *tcpShutdownConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.readStarted) })
	return c.Conn.Read(p)
}

func (l tcpShutdownListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpShutdownConn{Conn: c, readStarted: l.readStarted}, nil
}

func TestTCPListenerShutdownClosesIncompleteHandshake(t *testing.T) {
	spec := inboundFixture("slow", "127.0.0.1:1026")
	identity, _ := ecdh.X25519().GenerateKey(rand.Reader)
	runtime, err := newTCPListenerRuntime(spec, identity)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	readStarted := make(chan struct{})
	go func() { done <- serveTCPVPNServer(ctx, tcpShutdownListener{listener, readStarted}, runtime) }()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte{22})
	select {
	case <-readStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not reach the production Hello reader")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP listener shutdown left a handshake blocked")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("stopped listener left client connection open")
	}
}

func TestIndependentTCPXHTTPListenersWithNativeClient(t *testing.T) {
	client := os.Getenv("ATLANT_LOCAL_INBOUND_CLIENT_TEST")
	if client == "" {
		t.Skip("set path to native core go test binary")
	}
	isolateUsers(t)
	isolateReplay(t)
	key := bytes.Repeat([]byte{0x71}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	if err := usersStorage.AddUser("alice", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	cfg.WireVersion, cfg.SNI = 6, "unused.example.test"
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	type running struct {
		addr     string
		spec     InboundSpec
		identity *ecdh.PrivateKey
		stop     context.CancelFunc
		done     chan error
	}
	var listeners []running
	for _, id := range []string{"first", "second", "third"} {
		spec := inboundFixture(id, "127.0.0.1:1026")
		spec.SNI, spec.XHTTPPath = id+".example.test", "/"+id
		if id == "second" {
			spec.Transports = []string{"xhttp"}
			spec.XHTTPPath = "/"
		}
		if id == "third" {
			spec.Transports = []string{"tcp"}
		}
		identity, _ := ecdh.X25519().GenerateKey(rand.Reader)
		runtime, err := newTCPListenerRuntime(spec, identity)
		if err != nil {
			t.Fatal(err)
		}
		// Seed a local donor-certificate fixture, avoiding external DNS/TLS
		// requests. The VPN handshake and encryption remain production code.
		once := &sync.Once{}
		once.Do(func() {})
		sniInitOnceMap.Store(spec.SNI, once)
		donorCertMu.Lock()
		donorCertChains[spec.SNI] = [][]byte{generateValidASN1Cert(spec.SNI)}
		donorCertMu.Unlock()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		localCtx, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- serveTCPVPNServer(localCtx, listener, runtime) }()
		t.Cleanup(stop)
		listeners = append(listeners, running{listener.Addr().String(), spec, identity, stop, done})
	}
	probe := func(server running, transport, path string, deny bool) {
		t.Helper()
		cmd := exec.CommandContext(ctx, client, "-test.run=^TestLocalControlInboundProbe$", "-test.timeout=15s", "-test.v")
		cmd.Env = append(os.Environ(), "ATLANT_LOCAL_INBOUND_PROBE=1", "ATLANT_TEST_WIRE_VERSION=7",
			"ATLANT_TEST_SERVER="+server.addr, "ATLANT_TEST_SNI="+server.spec.SNI,
			"ATLANT_TEST_PBK="+hex.EncodeToString(key), "ATLANT_TEST_USER=alice", "ATLANT_TEST_FINGERPRINT=chrome",
			"ATLANT_TEST_SERVER_PUBKEY="+hex.EncodeToString(server.identity.PublicKey().Bytes()),
			"ATLANT_LOCAL_INBOUND_TRANSPORT="+transport, "ATLANT_LOCAL_INBOUND_PATH="+path,
			"ATLANT_LOCAL_INBOUND_EXPECT=allow")
		if deny {
			cmd.Env[len(cmd.Env)-1] = "ATLANT_LOCAL_INBOUND_EXPECT=deny"
		}
		output, err := cmd.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestLocalControlInboundProbe")) {
			t.Fatalf("native %s probe failed: %v\n%s", transport, err, output)
		}
	}
	probe(listeners[0], "tcp", "", false)
	probe(listeners[0], "mux", "", false)
	probe(listeners[0], "xhttp", "/first", false)
	probe(listeners[1], "xhttp", "/", false)
	probe(listeners[1], "tcp", "", true)
	probe(listeners[1], "xhttp", "/first", true)
	probe(listeners[1], "xhttp", "/api/v1/sync", true)
	probe(listeners[2], "tcp", "", false)
	probe(listeners[2], "xhttp", "/third", true)
	listeners[0].stop()
	select {
	case err := <-listeners[0].done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("first TCP listener did not stop")
	}
	probe(listeners[1], "xhttp", "/", false)
	for _, server := range listeners[1:] {
		server.stop()
		select {
		case err := <-server.done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("remaining TCP listener did not stop")
		}
	}
}
