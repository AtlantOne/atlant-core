package main

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/wire"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestInboundControllerQUICMetadataPreservesSessionAndListenerChangesReauthenticate(t *testing.T) {
	testInboundControllerQUICWithSNI(t, "localhost.")
}

func TestInboundControllerQUICUsesConfiguredMicrosoftSNI(t *testing.T) {
	testInboundControllerQUICWithSNI(t, "www.microsoft.com")
}

func testInboundControllerQUICWithSNI(t *testing.T, sni string) {
	isolateUsers(t)
	key := bytes.Repeat([]byte{0x51}, 32)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	record := inboundRecordFixture(t, "quic", freeInboundAddress(t))
	record.Settings.SNI = sni
	record.Settings.Transports = []string{"quic"}
	catalog := inboundCatalog{Initialized: true, Revision: 1, Inbounds: []inboundRecord{record}}
	previous := activeInboundSet.Load()
	c, err := startInboundController(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { c.Close(); activeInboundSet.Store(previous) }()
	ping := func() quicpeer.ClientConn {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		addr, _ := net.ResolveUDPAddr("udp", record.Settings.Listen)
		conn, closer, err := quicpeer.DialClient(ctx, &quic.Transport{Conn: packet}, addr, &tls.Config{ServerName: record.Settings.SNI}, quicpeer.ClientConfig(), 7, quicpeer.DirectCredentials{User: "alice", Key: key, ServerPublicKey: record.identity.PublicKey().Bytes()})
		if closer != nil {
			t.Cleanup(func() { closer.Close() })
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := quicpeer.AuthenticateClient(ctx, conn, "alice", key); err != nil {
			t.Fatal(err)
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stream.SetDeadline(time.Now().Add(2 * time.Second))
		if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x11, Destination: "speedtest:80"}, 32, 256); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stream, "PING apply\n"); err != nil {
			t.Fatal(err)
		}
		if reply, err := bufio.NewReader(stream).ReadString('\n'); err != nil || reply != "PONG apply\n" {
			t.Fatal("authenticated stream failed", reply, err)
		}
		stream.Close()
		stream.CancelRead(0)
		return conn
	}
	first := ping()
	candidate := inboundCatalog{Initialized: true, Revision: 2, Inbounds: append([]inboundRecord(nil), catalog.Inbounds...)}
	candidate.Inbounds[0].Settings.Name = "Applied QUIC"
	if restored, err := c.Apply(candidate); restored || err != nil {
		t.Fatal(restored, err)
	}
	select {
	case <-first.Context().Done():
		t.Fatal("renaming the inbound closed an authenticated QUIC session")
	default:
	}
	stream, err := first.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(2 * time.Second))
	if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x11, Destination: "speedtest:80"}, 32, 256); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, "PING apply\n"); err != nil {
		t.Fatal(err)
	}
	if reply, err := bufio.NewReader(stream).ReadString('\n'); err != nil || reply != "PONG apply\n" {
		t.Fatal("session unusable after rename", reply, err)
	}
	stream.Close()
	stream.CancelRead(0)
	candidate.Revision++
	candidate.Inbounds[0].Settings.Quic.KeepAlivePeriodSec = 5
	if restored, err := c.Apply(candidate); restored || err != nil {
		t.Fatal(restored, err)
	}
	select {
	case <-first.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("old QUIC session survived listener replacement")
	}
	second := ping()
	second.CloseWithError(0, "done")
}
