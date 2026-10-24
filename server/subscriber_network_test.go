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
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestSubscriberNativeClientsRespectInboundRevocation(t *testing.T) {
	client := os.Getenv("ATLANT_LOCAL_INBOUND_CLIENT_TEST")
	if client == "" {
		t.Skip("set path to native client probe test binary")
	}
	store, catalog, serverID := nativeSubscriberFixture(t)
	go runQuotaWorker()
	t.Cleanup(stopQuotaWorker)
	isolateReplay(t)
	s, _ := createNativeSubscriber(t, serverID)
	key, _ := hex.DecodeString(usersDB.Users[s.User].PBK)
	for _, record := range catalog.Inbounds {
		once := &sync.Once{}
		once.Do(func() {})
		sniInitOnceMap.Store(record.Settings.SNI, once)
		donorCertMu.Lock()
		donorCertChains[record.Settings.SNI] = [][]byte{generateValidASN1Cert(record.Settings.SNI)}
		donorCertMu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	running, err := startInboundSet(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	probe := func(index int, transport string, deny bool) {
		t.Helper()
		record := catalog.Inbounds[index]
		cmd := exec.CommandContext(ctx, client, "-test.run=^TestLocalControlInboundProbe$", "-test.timeout=15s", "-test.v")
		expect := "allow"
		if deny {
			expect = "deny"
		}
		cmd.Env = append(os.Environ(), "ATLANT_LOCAL_INBOUND_PROBE=1", "ATLANT_TEST_WIRE_VERSION=7", "ATLANT_TEST_SERVER="+record.Settings.Listen, "ATLANT_TEST_SNI="+record.Settings.SNI, "ATLANT_TEST_PBK="+hex.EncodeToString(key), "ATLANT_TEST_USER="+s.User, "ATLANT_TEST_FINGERPRINT=chrome", "ATLANT_TEST_SERVER_PUBKEY="+record.PublicKey, "ATLANT_LOCAL_INBOUND_TRANSPORT="+transport, "ATLANT_LOCAL_INBOUND_PATH="+record.Settings.XHTTPPath, "ATLANT_LOCAL_INBOUND_EXPECT="+expect)
		output, err := cmd.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: TestLocalControlInboundProbe")) {
			t.Fatalf("native %s authorization probe failed: %v\n%s", transport, err, output)
		}
	}
	dialQUIC := func(index int, deny bool) quicpeer.ClientConn {
		t.Helper()
		record := catalog.Inbounds[index]
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { packet.Close() })
		addr, _ := net.ResolveUDPAddr("udp", record.Settings.Listen)
		dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
		defer dialCancel()
		conn, closer, err := quicpeer.DialClient(dialCtx, &quic.Transport{Conn: packet}, addr, &tls.Config{ServerName: record.Settings.SNI}, quicpeer.ClientConfig(), 7, quicpeer.DirectCredentials{User: s.User, Key: key, ServerPublicKey: record.identity.PublicKey().Bytes()})
		if closer != nil {
			t.Cleanup(func() { closer.Close() })
		}
		if deny {
			if err == nil {
				t.Fatal("revoked QUIC Initial obtained a VPN connection")
			}
			return nil
		}
		if err != nil {
			t.Fatal("authorized QUIC rejected", err)
		}
		if err := quicpeer.AuthenticateClient(ctx, conn, s.User, key); err != nil {
			t.Fatal(err)
		}
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stream.SetDeadline(time.Now().Add(2 * time.Second))
		if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag(s.User), Protocol: 0x11, Destination: "speedtest:80"}, 32, 256); err != nil {
			t.Fatal(err)
		}
		io.WriteString(stream, "PING subscriber\n")
		if reply, err := bufio.NewReader(stream).ReadString('\n'); err != nil || reply != "PONG subscriber\n" {
			t.Fatal("QUIC stream failed", reply, err)
		}
		stream.Close()
		stream.CancelRead(0)
		return conn
	}
	probe(0, "tcp", false)
	probe(0, "mux", false)
	probe(0, "xhttp", false)
	first := dialQUIC(0, false)
	s.InboundRefs = s.InboundRefs[1:]
	if w := subscriptionRequest(t, http.MethodPut, s); w.Code != 200 {
		t.Fatal("could not revoke first inbound", w.Code)
	}
	select {
	case <-first.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("revoked QUIC session remained open")
	}
	probe(0, "tcp", true)
	probe(0, "xhttp", true)
	dialQUIC(0, true)
	probe(1, "tcp", false)
	probe(1, "xhttp", false)
	second := dialQUIC(1, false)
	list, err := readSubscriptions(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	s = list[0]
	s.Enabled = false
	if w := subscriptionRequest(t, http.MethodPut, s); w.Code != 200 {
		t.Fatal("could not disable subscriber", w.Code)
	}
	select {
	case <-second.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("disabled subscriber kept QUIC session")
	}
	probe(1, "tcp", true)
	probe(1, "xhttp", true)
	dialQUIC(1, true)
}
