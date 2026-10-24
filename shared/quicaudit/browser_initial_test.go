package quicaudit

import (
	"atlant.local/protocol/quicpeer"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestBrowserInitialOnWireAndCanceledHandshakeCleanup(t *testing.T) {
	for _, version := range []int{6, 7} {
		for _, passive := range []bool{false, true} {
			for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
				t.Run(fmt.Sprintf("wire%d/passive=%v/%s", version, passive, address), func(t *testing.T) { captureBrowserInitial(t, address, version, passive) })
			}
		}
	}
}

func captureBrowserInitial(t *testing.T, address string, version int, passive bool) {
	sink, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	// A VPN/firewall on the test host may block even ::1. Establish the raw UDP
	// baseline before attributing silence to the QUIC implementation.
	_ = sink.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, baselineWrite := packet.WriteTo([]byte{1}, sink.LocalAddr())
	var baseline [1]byte
	_, _, baselineRead := sink.ReadFrom(baseline[:])
	if baselineWrite != nil || baselineRead != nil {
		if address == "[::1]:0" {
			t.Skipf("IPv6 loopback UDP unavailable before QUIC: write=%v read=%v", baselineWrite, baselineRead)
		}
		t.Fatalf("UDP baseline: write=%v read=%v", baselineWrite, baselineRead)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	var direct []quicpeer.DirectCredentials
	if version == 7 {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		direct = []quicpeer.DirectCredentials{{User: "audit", Key: bytes.Repeat([]byte{7}, 32), ServerPublicKey: key.PublicKey().Bytes()}}
	}
	go func() {
		transportPacket := packet
		if passive {
			transportPacket = quicpeer.NativeClientSocket(packet)
		}
		conn, closer, err := quicpeer.DialClient(ctx, &quic.Transport{Conn: transportPacket}, sink.LocalAddr(), &tls.Config{ServerName: "observer.invalid", NextProtos: []string{"h3"}}, quicpeer.ClientConfig(), version, direct...)
		if conn != nil {
			_ = conn.CloseWithError(0, "capture complete")
		}
		if closer != nil {
			_ = closer.Close()
		}
		done <- err
	}()
	_ = sink.SetReadDeadline(time.Now().Add(2 * time.Second))
	var observer Observer
	var summary Summary
	var firstSeen [maxCrypto]bool
	for i := 0; i < 8; i++ {
		buf := make([]byte, 65535)
		n, _, err := sink.ReadFrom(buf)
		if err != nil {
			cancel()
			select {
			case dialErr := <-done:
				t.Fatalf("UDP capture failed: %v; dial: %v", err, dialErr)
			case <-time.After(time.Second):
			}
			t.Fatal(err)
		}
		summary, err = observer.Observe(buf[:n])
		if i == 0 {
			firstSeen = observer.seen
		}
		if err == nil {
			break
		}
		if !errors.Is(err, ErrIncomplete) {
			t.Fatal(err)
		}
	}
	if summary.SCIDLength != 0 || summary.DCIDLength != 8 || summary.ClientHello.SessionIDSize != 0 {
		t.Fatalf("unexpected Initial shape: %+v", summary)
	}
	head := 0
	for head < len(firstSeen) && firstSeen[head] {
		head++
	}
	if head < 55 || head > 84 || !firstSeen[summary.ClientHello.HelloSize-1] {
		t.Fatal("first Initial must carry observed Chrome head/tail layout")
	}
	if len(summary.PacketNumbers) < 2 || summary.PacketNumbers[0] != 1 || summary.PacketNumbers[1] != 2 {
		t.Fatalf("packet numbers: %v", summary.PacketNumbers)
	}
	wantSize := 1250
	if address == "[::1]:0" {
		wantSize = 1230
	}
	if len(summary.DatagramSizes) != 2 || summary.DatagramSizes[0] != wantSize || summary.DatagramSizes[1] != wantSize {
		t.Fatalf("Chrome cold flight packet sizes: %v", summary.DatagramSizes)
	}
	if !reflect.DeepEqual(summary.ClientHello.CipherSuites, []uint16{0x1301, 0x1302, 0x1303}) {
		t.Fatalf("cipher suites: %v", summary.ClientHello.CipherSuites)
	}
	if !reflect.DeepEqual(summary.ClientHello.KeyShareGroups, []uint16{4588, 29}) {
		t.Fatalf("key shares: %v", summary.ClientHello.KeyShareGroups)
	}
	if !reflect.DeepEqual(summary.ClientHello.ALPN, []string{"h3"}) {
		t.Fatal("ALPN differs")
	}
	// Independent reference: quic-fingerprint-conformance corpus/multi_chrome_146,
	// expected.json, cold handshake conn_key 099f8dea201f93b7. This compares public
	// fields, not packet timing or an entire browser session.
	if !reflect.DeepEqual(summary.ClientHello.SupportedGroups, []uint16{4588, 29, 23, 24}) ||
		!reflect.DeepEqual(summary.ClientHello.SupportedVersions, []uint16{772}) ||
		!reflect.DeepEqual(summary.ClientHello.SignatureSchemes, []uint16{1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513}) {
		t.Fatalf("TLS fields differ from captured Chrome 146: %+v", summary.ClientHello)
	}
	extensions := append([]uint16(nil), summary.ClientHello.Extensions...)
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	if !reflect.DeepEqual(extensions, []uint16{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 65037}) {
		t.Fatalf("TLS extensions differ from captured Chrome 146: %v", extensions)
	}
	limits := map[uint64]uint64{1: 30000, 3: 1472, 4: 15728640, 5: 6291456, 6: 6291456, 7: 6291456, 8: 100, 9: 103}
	for _, p := range summary.ClientHello.TransportParameters {
		if want, ok := limits[p.ID]; ok {
			if p.Integer == nil || *p.Integer != want {
				t.Fatalf("transport parameter %d", p.ID)
			}
			delete(limits, p.ID)
		}
	}
	if len(limits) != 0 {
		t.Fatal("missing transport limits")
	}
	t.Logf("datagram sizes=%v packet numbers=%v TLS extensions=%v", summary.DatagramSizes, summary.PacketNumbers, summary.ClientHello.Extensions)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled browser handshake did not stop")
	}
}
