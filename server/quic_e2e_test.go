package main

import (
	"atlant.local/protocol/quicadmission"
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/quicreality"
	"atlant.local/protocol/wire"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func TestSecureQUICThroughProductionDemuxAndStreamHandler(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		for _, format := range []int{2, 3, 4, 6} {
			t.Run(fmt.Sprintf("%s/wire%d", version.String(), format), func(t *testing.T) { testSecureQUICServer(t, version, format, false) })
		}
	}
}

// A known, unspent CID can admit TLS before peer proof. This regression checks
// that admission never grants proxy access; it does NOT claim that the server
// certificate is hidden from an attacker racing with a copied unused token.
func TestQUICAdmissionCannotReplaceMutualPeerAuthentication(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		for _, format := range []int{3, 4, 6} {
			t.Run(fmt.Sprintf("%s/wire%d", version, format), func(t *testing.T) { testSecureQUICServer(t, version, format, true) })
		}
	}
}

func TestWire6CapturedInitialCannotClaimAdmissionFromOtherPort(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) { testSecureQUICServer(t, version, 6, false, true) })
	}
}

func TestBrowserWire6WithProductionRetryAndMutualAuthentication(t *testing.T) {
	testSecureQUICServer(t, quic.Version1, 6, false, true, true)
}

func TestDirectQUICRealityWire7WithoutTCPBootstrap(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) { testSecureQUICServer(t, version, 7, false) })
	}
}

func TestDirectQUICRealityWire7RejectsWrongPeerProof(t *testing.T) {
	testSecureQUICServer(t, quic.Version1, 7, true)
}

// Replay both the original and the Retry-bearing Initial before the real
// sender. All packets are registered through the real authenticated control
// handler; only the attacker socket has a different source port.
type replayInitialConn struct {
	net.PacketConn
	attacker net.PacketConn
	t        *testing.T
	seen     [2]bool
}

func (c *replayInitialConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	initial, err := quicadmission.InitialPacket(p)
	if err != nil || !initial {
		return c.PacketConn.WriteTo(p, addr)
	}
	offset := 7 + int(p[5])
	length, _, err := quicvarint.Parse(p[offset:]) // InitialPacket requires empty client SCID.
	if err != nil {
		return 0, err
	}
	stage := 0
	if length != 0 {
		stage = 1
	}
	if !c.seen[stage] {
		c.seen[stage] = true
		if _, err := c.attacker.WriteTo(p, addr); err != nil {
			return 0, err
		}
		_ = c.attacker.SetReadDeadline(time.Now().Add(time.Second))
		var response [2048]byte
		if _, _, err := c.attacker.ReadFrom(response[:]); err != nil {
			return 0, fmt.Errorf("replay stage %d: %w", stage, err)
		}
		c.t.Logf("captured Initial replayed first from competing port, stage=%d", stage)
	}
	return c.PacketConn.WriteTo(p, addr)
}

func testSecureQUICServer(t *testing.T, version quic.Version, format int, wrongProof bool, replay ...bool) {
	isolateUsers(t)
	if format == 7 {
		previous := serverStaticECDH
		serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
		defer func() { serverStaticECDH = previous }()
		cfg.WireVersion, cfg.LegacyWire = 7, false
	}
	key := bytes.Repeat([]byte{9}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	_ = usersStorage.AddUser("alice", hex.EncodeToString(key))
	previous := activeAdmission.Load()
	defer activeAdmission.Store(previous)
	var gate *admissionGate
	clientSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	var clientPacket net.PacketConn = clientSocket
	var replayConn *replayInitialConn
	var directReplay *replayDirectFlight
	if len(replay) != 0 && replay[0] {
		attacker, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer attacker.Close()
		replayConn = &replayInitialConn{PacketConn: clientSocket, attacker: attacker, t: t}
		clientPacket = replayConn
		if format == 7 {
			directReplay = &replayDirectFlight{PacketConn: clientSocket, attacker: attacker, t: t}
			clientPacket = directReplay
			replayConn = nil
		}
	}
	var generator quic.ConnectionIDGenerator = quicpeer.NewCIDGenerator("alice", key)
	if format == 3 || format == 4 || format == 6 {
		cfg.WireVersion = format
		cfg.LegacyWire = false
		gate, _ = newAdmissionGate()
		activeAdmission.Store(gate)
		client, server := loopbackControlPair(t)
		go handleStream(server, "alice", format)
		var pool *quicadmission.CIDPool
		if format == 4 || format == 6 {
			var bound *quicadmission.BoundPacketConn
			pool, bound, err = quicadmission.FetchBoundPoolVersion(context.Background(), client, clientPacket, byte(format))
			if err == nil {
				clientPacket = bound
				defer bound.Close()
			}
		} else {
			pool, err = quicadmission.FetchPool(context.Background(), client)
		}
		if err != nil {
			t.Fatal(err)
		}
		generator = pool
		if format == 4 || format == 6 {
			generator = &quicadmission.ZeroCIDGenerator{}
		}
	} else {
		activeAdmission.Store(nil)
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	serverSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	demux, err := NewDemuxPacketConn(serverSocket, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer demux.Close()
	serverTransport := &quic.Transport{Conn: demux, ConnectionIDGenerator: &serverConnIDGenerator{demux: demux}}
	serverConfig := &quic.Config{EnableDatagrams: true, Versions: []quic.Version{version}}
	if gate != nil {
		serverTransport.ConnContext = gate.connContext
		if format == 6 {
			serverTransport.VerifySourceAddress = func(net.Addr) bool { return true }
		}
		serverConfig.Tracer = gate.tracer
	}
	defer serverTransport.Close()
	serverTLS := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"h3"}}
	if format == 7 {
		serverTransport.ConnContext = demux.direct.connContext
		serverTransport.VerifySourceAddress = func(net.Addr) bool { return true }
		serverConfig.Tracer = demux.direct.tracer
		serverTLS.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			a, err := directAdmission(info.Context())
			if err != nil {
				return nil, err
			}
			c, err := quicreality.Certificate("localhost", *a)
			return &c, err
		}
		serverTLS.Certificates = nil
	}
	listener, err := serverTransport.Listen(serverTLS, serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err == nil {
			handleQUICSession(conn, nil)
		}
		serverDone <- err
	}()
	clientTransport := &quic.Transport{Conn: clientPacket, ConnectionIDGenerator: generator}
	defer clientTransport.Close()
	clientVersion := 4 // stock transport for protocol-version matrix tests
	if len(replay) > 1 && replay[1] {
		clientVersion = 6
	}
	var direct []quicpeer.DirectCredentials
	if format == 7 {
		clientVersion = 7
		direct = []quicpeer.DirectCredentials{{User: "alice", Key: key, ServerPublicKey: serverStaticECDH.PublicKey().Bytes()}}
	}
	conn, closer, err := quicpeer.DialClient(ctx, clientTransport, demux.LocalAddr(), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true, Versions: []quic.Version{version}, InitialPacketSize: 1200, DisablePathMTUDiscovery: true}, clientVersion, direct...)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.CloseWithError(0, "test finished")
		select {
		case err := <-serverDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("server handler leaked after connection closed")
		}
	}()
	if wrongProof {
		wrongKey := bytes.Repeat([]byte{0xa7}, 32)
		if err := quicpeer.AuthenticateClient(ctx, conn, "alice", wrongKey); err == nil {
			t.Fatal("admission token granted access without the correct peer proof")
		}
		select {
		case <-conn.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("failed peer proof left tunnel alive")
		}
		return
	}
	if err := quicpeer.AuthenticateClient(ctx, conn, "alice", key); err != nil {
		t.Fatal(err)
	}
	if replayConn != nil && replayConn.seen != [2]bool{true, true} {
		t.Fatal("did not exercise both pre-Retry and post-Retry replay")
	}
	if directReplay != nil && directReplay.seen != [2]bool{true, true} {
		t.Fatal("direct flight replay stages not exercised")
	}
	// An HTTP/3 Initial is >=1200 bytes before our destination metadata. A
	// healthy authenticated outer QUIC session can still reject this DATAGRAM.
	// That is a PMTU limitation, not proof that the network blocks UDP.
	packet := make([]byte, 1200+10+len("video.example:443"))
	if clientVersion == 6 || clientVersion == 7 {
		packet = make([]byte, 65536)
	}
	var sizeError *quic.DatagramTooLargeError
	if err := conn.SendDatagram(packet); !errors.As(err, &sizeError) {
		t.Fatalf("expected encapsulated HTTP/3 packet size error, got %v", err)
	}
	if err := conn.Context().Err(); err != nil {
		t.Fatalf("size failure killed healthy QUIC connection: %v", err)
	}
	t.Logf("HTTP/3 payload %d exceeds DATAGRAM maximum %d; authenticated stream remains usable", len(packet), sizeError.MaxDatagramPayloadSize)
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	header := wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x11, Destination: "speedtest:80"}
	if err := wire.WriteQUICHeader(stream, header, 2048, 2048); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(stream, "PING verify\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil || line != "PONG verify\n" {
		t.Fatalf("production stream reply=%q error=%v", line, err)
	}
	// Explicitly isolated Linux namespace only: never disable the SSRF guard
	// just to test UDP relay against an ordinary localhost/private destination.
	if os.Getenv("ATLANT_TEST_UDP_TARGET") == "192.0.2.1" {
		testProductionUDPStream(t, ctx, conn)
		testProductionDNSPolicy(t, ctx, conn)
	}
}

// Admission now reserves a real peer IP. net.Pipe reports the synthetic
// address "pipe", which must not be admitted as an Internet client address.
func loopbackControlPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// Runs only in the opt-in network namespace, against a local DNS-shaped echo
// fixture bound to public-safe test address :53. Exercises both production
// QUIC UDP relay paths, not just the response filter in isolation.
func testProductionDNSPolicy(t *testing.T, ctx context.Context, conn quicpeer.ClientConn) {
	t.Helper()
	configMu.Lock()
	previous := cfg.DNSIPv4Only
	cfg.DNSIPv4Only = true
	configMu.Unlock()
	defer func() { configMu.Lock(); cfg.DNSIPv4Only = previous; configMu.Unlock() }()
	echo, err := net.ListenPacket("udp", "192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := echo.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buffer[:n], peer)
		}
	}()
	destination := "192.0.2.1:53"
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x12, Destination: destination}, 32, 256); err != nil {
		t.Fatal(err)
	}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.Type(65)} {
		packet := policyDNSReply(t, qtype)
		frame := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(frame, uint16(len(packet)))
		copy(frame[2:], packet)
		if err := writeFull(stream, frame); err != nil {
			t.Fatal(err)
		}
		var prefix [2]byte
		if _, err := io.ReadFull(stream, prefix[:]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
		if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, ipv4DNSResponse(packet)) {
			t.Fatalf("stream policy qtype=%d: %v", qtype, err)
		}
		// DATAGRAM: [userTag][flowID][destination length][destination][packet].
		dgram := make([]byte, 10+len(destination)+len(packet))
		tag := getUserTag("alice")
		copy(dgram, tag[:])
		binary.BigEndian.PutUint32(dgram[4:8], 100+uint32(qtype))
		binary.BigEndian.PutUint16(dgram[8:10], uint16(len(destination)))
		copy(dgram[10:], destination)
		copy(dgram[10+len(destination):], packet)
		if err := conn.SendDatagram(dgram); err != nil {
			t.Fatal(err)
		}
		reply, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(reply) < 6+len(destination) || !bytes.Equal(reply[6+len(destination):], ipv4DNSResponse(packet)) {
			t.Fatalf("datagram policy qtype=%d corrupted", qtype)
		}
	}
}

func testProductionUDPStream(t *testing.T, ctx context.Context, conn quicpeer.ClientConn) {
	t.Helper()
	echo, err := net.ListenPacket("udp", "192.0.2.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:n], addr)
		}
	}()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag("alice"), Protocol: 0x12, Destination: echo.LocalAddr().String()}, 32, 256); err != nil {
		t.Fatal(err)
	}
	var prefix [2]byte
	for _, size := range []int{1, 1200, 1350, 2048, 8192, 65507, 0, 17} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		binary.BigEndian.PutUint16(prefix[:], uint16(size))
		if err := writeFull(stream, append(prefix[:], payload...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(stream, prefix[:]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
		if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("UDP size=%d err=%v", size, err)
		}
	}
}
