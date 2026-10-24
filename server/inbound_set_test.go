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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func freeInboundAddress(t *testing.T) string {
	t.Helper()
	// Windows has different excluded TCP/UDP ranges. TCP :0 may walk through
	// a whole UDP-reserved range; sample explicit unprivileged ports instead.
	var lastErr error
	for range 100 {
		var sample [2]byte
		if _, err := rand.Read(sample[:]); err != nil {
			t.Fatal(err)
		}
		candidate := net.JoinHostPort("127.0.0.1", strconv.Itoa(10000+int(binary.BigEndian.Uint16(sample[:]))%30000))
		listener, err := net.Listen("tcp", candidate)
		if err != nil {
			lastErr = err
			continue
		}
		address := listener.Addr().String()
		udp, err := net.ListenPacket("udp", address)
		listener.Close()
		if err == nil {
			udp.Close()
			return address
		}
		lastErr = err
	}
	t.Fatal("could not reserve a test TCP/UDP port", lastErr)
	return ""
}

func inboundRecordFixture(t *testing.T, id, address string) inboundRecord {
	t.Helper()
	identity, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture(id, address)
	spec.Transports = []string{"tcp"}
	return inboundRecord{Settings: spec, identity: identity, PublicKey: hex.EncodeToString(identity.PublicKey().Bytes())}
}

func TestInboundSetBindFailureReleasesCandidateButNotForeignSocket(t *testing.T) {
	occupied, err := net.ListenPacket("udp", freeInboundAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	address := occupied.LocalAddr().String()
	probe, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	record := inboundRecordFixture(t, "conflict", address)
	record.Settings.Transports = []string{"tcp", "quic"}
	if running, err := startInboundSet(context.Background(), inboundCatalog{Initialized: true, Revision: 1, Inbounds: []inboundRecord{record}}); err == nil {
		running.Close()
		t.Fatal("occupied UDP port accepted")
	}
	probe, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatal("candidate TCP socket leaked after UDP bind failure", err)
	}
	probe.Close()
	if stolen, err := net.ListenPacket("udp", address); err == nil {
		stolen.Close()
		t.Fatal("foreign UDP listener was closed")
	}
}

func TestQUICDonorResolutionHonorsCancellationAndRejectsBadEndpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if donor, err := newDecoyNAT(ctx, nil, "localhost.:443"); !errors.Is(err, context.Canceled) {
		if donor != nil {
			donor.Close()
		}
		t.Fatal("canceled startup continued donor initialization", err)
	}
	for _, endpoint := range []string{"127.0.0.1:0", ":443", "127.0.0.1:http", "not-an-endpoint"} {
		if donor, err := newDecoyNAT(context.Background(), nil, endpoint); err == nil {
			if donor != nil {
				donor.Close()
			}
			t.Fatal("invalid donor endpoint accepted", endpoint)
		}
	}
}

func TestInboundSetUnexpectedListenerExitStopsOtherOwnedListeners(t *testing.T) {
	first := inboundRecordFixture(t, "first", freeInboundAddress(t))
	second := inboundRecordFixture(t, "second", freeInboundAddress(t))
	running, err := startInboundSet(context.Background(), inboundCatalog{Initialized: true, Revision: 2, Inbounds: []inboundRecord{first, second}})
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	running.bindings[0].tcp.Close()
	done := make(chan error, 1)
	go func() { done <- running.Wait() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "first TCP") {
			t.Fatal("listener failure was lost", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener failure did not stop set")
	}
	running.Close()
	for _, record := range []inboundRecord{first, second} {
		probe, err := net.Listen("tcp", record.Settings.Listen)
		if err != nil {
			t.Fatal("failed set left a listener active", err)
		}
		probe.Close()
	}
}

func TestInboundSetRestartsStoredQUICIdentityAndDisabledBindings(t *testing.T) {
	isolateUsers(t)
	key := bytes.Repeat([]byte{0x38}, 32)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("live", freeInboundAddress(t))
	spec.SNI = "localhost."
	record, revision, err := store.putInbound(ctx, spec, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	disabled := inboundFixture("disabled", freeInboundAddress(t))
	disabled.Enabled = false
	if _, _, err := store.putInbound(ctx, disabled, revision, true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		catalog, err := store.readInboundCatalog(ctx)
		if err != nil {
			t.Fatal(err)
		}
		running, err := startInboundSet(ctx, catalog)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(running.Close)
		if len(running.bindings) != 1 || running.revision != 3 {
			t.Fatal("disabled inbound started or revision lost")
		}
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr, _ := net.ResolveUDPAddr("udp", spec.Listen)
		conn, closer, err := quicpeer.DialClient(ctx, &quic.Transport{Conn: packet}, addr, &tls.Config{ServerName: spec.SNI}, quicpeer.ClientConfig(), 7,
			quicpeer.DirectCredentials{User: "alice", Key: key, ServerPublicKey: record.identity.PublicKey().Bytes()})
		if closer != nil {
			defer closer.Close()
		}
		if err != nil {
			packet.Close()
			t.Fatal("stored identity did not reconnect", err)
		}
		if err := quicpeer.AuthenticateClient(ctx, conn, "alice", key); err != nil {
			t.Fatal(err)
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.SetDeadline(time.Now().Add(time.Second))
		if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x11, Destination: "speedtest:80"}, 32, 256); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, "PING catalog\n"); err != nil {
			t.Fatal(err)
		}
		if reply, err := bufio.NewReader(stream).ReadString('\n'); err != nil || reply != "PONG catalog\n" {
			t.Fatal("native catalog stream failed", reply, err)
		}
		stream.Close()
		stream.CancelRead(0)
		conn.CloseWithError(0, "done")
		packet.Close()
		running.Close()
		if !errors.Is(running.Wait(), context.Canceled) {
			t.Fatal("planned stop reported as a listener failure")
		}
		probe, err := net.Listen("tcp", disabled.Listen)
		if err != nil {
			t.Fatal("disabled inbound reserved a TCP socket", err)
		}
		probe.Close()
	}
}
