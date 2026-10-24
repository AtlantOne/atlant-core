//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"atlant.local/protocol/quicadmission"
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/settings"
	"atlant.local/protocol/wire"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// ObfMode defines UDP obfuscation mode.
type ObfMode uint8

const (
	ObfChaCha20 ObfMode = iota
	ObfSTUN
)

// RealityQUICPacketConn passes native QUIC packets through unchanged.
type RealityQUICPacketConn struct {
	net.PacketConn
	secretKey []byte
}

func NewRealityQUICPacketConn(conn net.PacketConn, secretKey []byte) *RealityQUICPacketConn {
	return &RealityQUICPacketConn{
		PacketConn: conn,
		secretKey:  secretKey,
	}
}

func (r *RealityQUICPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return r.PacketConn.WriteTo(p, addr)
}

// RealityConnIDGenerator implements quic.ConnectionIDGenerator
// generating unique 20-byte authenticated SCIDs through the shared codec.
type RealityConnIDGenerator struct{ generator *quicpeer.CIDGenerator }

func NewRealityConnIDGenerator(user string, key []byte) *RealityConnIDGenerator {
	return &RealityConnIDGenerator{generator: quicpeer.NewCIDGenerator(user, key)}
}

func (g *RealityConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return g.generator.GenerateConnectionID()
}
func (g *RealityConnIDGenerator) ConnectionIDLen() int { return g.generator.ConnectionIDLen() }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BrutalPacer limits application writes; quic-go still controls congestion.
type BrutalPacer struct {
	rateBps uint64
	mu      sync.Mutex
	last    time.Time
}

func NewBrutalPacer(mbps uint64) *BrutalPacer {
	return &BrutalPacer{
		rateBps: mbps * 1024 * 1024,
		last:    time.Now(),
	}
}

func (p *BrutalPacer) Pace(packetSize int) {
	if p == nil || p.rateBps == 0 {
		return
	}
	interval := time.Duration(float64(packetSize*8) / float64(p.rateBps) * float64(time.Second))
	p.mu.Lock()
	defer p.mu.Unlock()
	target := p.last.Add(interval)
	now := time.Now()
	if target.After(now) {
		time.Sleep(target.Sub(now))
		p.last = target
	} else {
		p.last = now
	}
}

type quicNetStream struct {
	quicpeer.ClientStream
	pacer      *BrutalPacer
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicNetStream) LocalAddr() net.Addr {
	return wire.StreamAddr(q.localAddr)
}

func (q *quicNetStream) RemoteAddr() net.Addr {
	return wire.StreamAddr(q.remoteAddr)
}

func (q *quicNetStream) Write(b []byte) (int, error) {
	if q.pacer != nil {
		q.pacer.Pace(len(b))
	}
	return q.ClientStream.Write(b)
}

func (q *quicNetStream) CloseWrite() error {
	return q.ClientStream.Close()
}

// net.Conn.Close must unblock both Read and Write. quic.Stream.Close only
// sends FIN on the write side; using it alone left relay readers stuck until
// the whole pooled connection timed out. Keep graceful FIN in CloseWrite.
func (q *quicNetStream) Close() error {
	q.ClientStream.CancelRead(0)
	q.ClientStream.CancelWrite(0)
	return nil
}

var (
	quicClientConn      quicpeer.ClientConn
	quicClientTransport io.Closer
	quicClientPacket    net.PacketConn
	quicClientMu        sync.Mutex
	quicDialInProgress  bool
	quicDialWaitChan    chan struct{}
	quicDialLastErr     error
	quicDialCancel      context.CancelFunc
	quicGeneration      uint64
	quicSessionCache                 = tls.NewLRUClientSessionCache(64)
	quicPacer           *BrutalPacer = nil // Unlimited line rate (no artificial pacing)
	quicFlowNAT                      = make(map[uint32]chan []byte)
	quicFlowNATMu       sync.RWMutex
	flowCounter         uint32
	recoveryMu          sync.Mutex
	recoveryActive      bool
	recoveryContext     context.Context
)

func closeQUICClient(reason string) {
	quicClientMu.Lock()
	quicGeneration++
	if quicDialCancel != nil {
		quicDialCancel()
	}
	conn := quicClientConn
	transport := quicClientTransport
	packet := quicClientPacket
	quicClientConn = nil
	quicClientTransport = nil
	quicClientPacket = nil
	quicDialLastErr = nil
	quicClientMu.Unlock()

	if conn != nil {
		_ = conn.CloseWithError(0, reason)
	}
	if transport != nil {
		_ = transport.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
}

func registerFlowSubscriber(ch chan []byte) uint32 {
	quicFlowNATMu.Lock()
	defer quicFlowNATMu.Unlock()
	for {
		flowCounter++
		if flowCounter == 0 {
			flowCounter = 1
		}
		if _, exists := quicFlowNAT[flowCounter]; !exists {
			quicFlowNAT[flowCounter] = ch
			return flowCounter
		}
	}
}

func unregisterFlowSubscriber(flowID uint32) {
	quicFlowNATMu.Lock()
	delete(quicFlowNAT, flowID)
	quicFlowNATMu.Unlock()
}

func getOrDialQUICClient(cfg *Config) (quicpeer.ClientConn, error) {
	sessionCtx := cfg.context()
	if err := sessionCtx.Err(); err != nil {
		return nil, err
	}
	if err := settings.Profile(cfg.ServerAddr, cfg.SNI, cfg.PBK, cfg.User); err != nil {
		return nil, err
	}
	quicClientMu.Lock()
	if quicClientConn != nil {
		select {
		case <-quicClientConn.Context().Done():
			if quicClientTransport != nil {
				_ = quicClientTransport.Close()
				quicClientTransport = nil
			}
			if quicClientPacket != nil {
				_ = quicClientPacket.Close()
				quicClientPacket = nil
			}
			quicClientConn = nil
		default:
			c := quicClientConn
			quicClientMu.Unlock()
			return c, nil
		}
	}

	// Single-flight: If dial is already in progress, wait on the shared channel
	if quicDialInProgress {
		waitCh := quicDialWaitChan
		quicClientMu.Unlock()
		select {
		case <-sessionCtx.Done():
			return nil, sessionCtx.Err()
		case <-waitCh:
		}
		quicClientMu.Lock()
		err := quicDialLastErr
		quicClientMu.Unlock()
		if err != nil {
			return nil, err
		}
		return getOrDialQUICClient(cfg)
	}

	quicDialInProgress = true
	quicDialWaitChan = make(chan struct{})
	generation := quicGeneration
	dialTimeout := 4 * time.Second
	if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		dialTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(sessionCtx, dialTimeout)
	quicDialCancel = cancel
	quicClientMu.Unlock()
	defer cancel()

	defer func() {
		quicClientMu.Lock()
		quicDialInProgress = false
		quicDialCancel = nil
		close(quicDialWaitChan)
		quicClientMu.Unlock()
	}()

	targetAddr := cfg.ServerAddr
	if IsPortHoppingEnabled() {
		host, _, err := net.SplitHostPort(cfg.ServerAddr)
		if err == nil {
			hopPort := 20000 + int((time.Now().Unix()/120)%30000)
			targetAddr = net.JoinHostPort(host, strconv.Itoa(hopPort))
		}
	}
	serverUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		dialErr := fmt.Errorf("resolve server addr: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}

	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		dialErr := fmt.Errorf("listen packet: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}
	if uConn, ok := pc.(*net.UDPConn); ok {
		_ = uConn.SetReadBuffer(8 * 1024 * 1024)
		_ = uConn.SetWriteBuffer(8 * 1024 * 1024)
		rc, err := uConn.SyscallConn()
		if err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("access QUIC socket: %w", err)
		}
		var protectErr error
		if err := rc.Control(func(fd uintptr) { protectErr = protectSocket(int(fd)) }); err != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("control QUIC socket: %w", err)
		}
		if protectErr != nil {
			_ = pc.Close()
			return nil, fmt.Errorf("protect QUIC socket: %w", protectErr)
		}
	}

	userKey := parsePBKBytes(cfg.PBK)
	var generator quic.ConnectionIDGenerator = NewRealityConnIDGenerator(cfg.User, userKey)
	if cfg.WireVersion == 3 || cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		bootstrap, err := dialQUICBootstrap(cfg)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("REALITY CID bootstrap: %w", err)
		}
		var pool *quicadmission.CIDPool
		if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
			var bound *quicadmission.BoundPacketConn
			pool, bound, err = quicadmission.FetchBoundPoolVersion(ctx, bootstrap, pc, byte(cfg.WireVersion))
			if err == nil {
				pc = bound
				defer bound.CloseBootstrap()
			}
		} else {
			pool, err = quicadmission.FetchPool(ctx, bootstrap)
		}
		if err != nil {
			pc.Close()
			return nil, err
		}
		generator = pool
		if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
			generator = &quicadmission.ZeroCIDGenerator{}
		}
	}
	transport := &quic.Transport{
		// The socket was protected above. Passing it through keeps UDP OOB and
		// batching available without bypassing older admission wrappers in pc.
		Conn:                  quicpeer.NativeClientSocket(pc),
		ConnectionIDGenerator: generator,
	}

	var sessionCache tls.ClientSessionCache
	if IsZeroRttEnabled() {
		sessionCache = quicSessionCache
	}

	// Synchronize SNI for QUIC with server (if empty or microsoft.com, use speed.cloudflare.com)
	quicSNI := cfg.SNI
	if quicSNI == "" || strings.Contains(strings.ToLower(quicSNI), "microsoft.com") {
		quicSNI = "speed.cloudflare.com"
	}

	tlsConfig := &tls.Config{
		ServerName:         quicSNI,
		InsecureSkipVerify: true,
		ClientSessionCache: sessionCache,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer cert")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if err := cert.VerifyHostname(quicSNI); err != nil && cert.Subject.CommonName != quicSNI {
				if err2 := cert.VerifyHostname(cfg.SNI); err2 != nil && cert.Subject.CommonName != cfg.SNI {
					return fmt.Errorf("peer cert does not match SNI %s: %w", quicSNI, err)
				}
			}
			return nil
		},
		NextProtos: []string{"h3"},
	}
	quicpeer.ConfigureTLSPrivacy(tlsConfig, cfg.WireVersion)

	quicConfig := quicpeer.ClientConfig()

	var direct []quicpeer.DirectCredentials
	if cfg.WireVersion == 7 {
		serverKey, err := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
		if err != nil || len(serverKey) != 32 {
			_ = pc.Close()
			return nil, fmt.Errorf("invalid pinned direct QUIC server key")
		}
		direct = []quicpeer.DirectCredentials{{User: cfg.User, Key: userKey, ServerPublicKey: serverKey}}
	}
	conn, closer, err := quicpeer.DialClient(ctx, transport, serverUDPAddr, tlsConfig, quicConfig, cfg.WireVersion, direct...)
	if err != nil {
		_ = closer.Close()
		_ = pc.Close()
		dialErr := fmt.Errorf("quic dial: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}

	if err := quicpeer.AuthenticateClient(ctx, conn, cfg.User, userKey); err != nil {
		_ = conn.CloseWithError(0x100, "peer authentication failed")
		_ = closer.Close()
		_ = pc.Close()
		quicClientMu.Lock()
		quicDialLastErr = err
		quicClientMu.Unlock()
		return nil, err
	}
	quicClientMu.Lock()
	if generation != quicGeneration || sessionCtx.Err() != nil {
		quicClientMu.Unlock()
		_ = conn.CloseWithError(0, "stale VPN or network")
		_ = closer.Close()
		_ = pc.Close()
		return nil, context.Canceled
	}
	quicClientConn = conn
	quicClientTransport = closer
	quicClientPacket = pc
	quicDialLastErr = nil
	quicClientMu.Unlock()

	go runQUICDatagramDispatcher(conn)

	return conn, nil
}

func startDecoyTrafficGenerator(cfg *Config) {
	go func() {
		ticker := time.NewTicker(20 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cfg.context().Done():
				return
			case <-ticker.C:
			}
			if !IsDecoyTrafficEnabled() {
				continue
			}
			conn, err := dialQUICStream(cfg, "tcp", net.JoinHostPort(cfg.SNI, "443"))
			if err == nil {
				req := fmt.Sprintf("GET /favicon.ico HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", cfg.SNI)
				_, _ = conn.Write([]byte(req))
				buf := make([]byte, 512)
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = conn.Read(buf)
				_ = conn.Close()
			}
		}
	}()
}

func runQUICDatagramDispatcher(conn quicpeer.ClientConn) {
	ctx := conn.Context()
	for {
		dgram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			break
		}
		// Expected format from server: [4B flowID][2B destLen][destAddr][payload]
		if len(dgram) < 6 {
			continue
		}
		flowID := binary.BigEndian.Uint32(dgram[:4])
		destLen := int(binary.BigEndian.Uint16(dgram[4:6]))
		if len(dgram) < 6+destLen {
			continue
		}
		payload := dgram[6+destLen:]

		quicFlowNATMu.RLock()
		ch, ok := quicFlowNAT[flowID]
		if ok {
			select {
			case ch <- payload:
			default:
			}
		}
		quicFlowNATMu.RUnlock()
	}
}

func dialQUICStream(cfg *Config, network, addr string) (net.Conn, error) {
	conn, err := getOrDialQUICClient(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(cfg.context(), 10*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	var protoByte byte = 0x11
	if network == "udp" {
		protoByte = 0x12
	}
	minPadding, maxPadding := 0, 0
	if cfg.PaddingEnabled {
		minPadding, maxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	}
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag(cfg.User), Protocol: protoByte, Destination: addr}, minPadding, maxPadding); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return &quicNetStream{
		ClientStream: stream,
		pacer:        quicPacer,
		localAddr:    conn.LocalAddr(),
		remoteAddr:   conn.RemoteAddr(),
	}, nil
}

func startUDPRecoveryProbe(cfg *Config) {
	ctx := cfg.context()
	if ctx.Err() != nil {
		return
	}
	recoveryMu.Lock()
	if recoveryActive && recoveryContext != nil && recoveryContext.Err() == nil {
		recoveryMu.Unlock()
		return
	}
	recoveryActive = true
	recoveryContext = ctx
	recoveryMu.Unlock()

	go func() {
		defer func() {
			recoveryMu.Lock()
			if recoveryContext == ctx {
				recoveryActive = false
				recoveryContext = nil
			}
			recoveryMu.Unlock()
		}()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for i := 0; i < 30; i++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			if !isUDPBlocked() {
				return
			}
			// A canceled session must never recover a connection for an old profile.
			if ctx.Err() != nil {
				return
			}

			if _, err := getOrDialQUICClient(cfg); err == nil {
				log.Printf("[UDP-RECOVERY] UDP channel restored, reverting to QUIC datagram tunnel")
				setUDPBlocked(false)
				return
			}
		}
	}()
}

func handleUDPViaDatagramTunnel(gvisorConn net.Conn, cfg *Config, destAddr string) bool {
	if preferQUICUDPStream(destAddr) {
		routeUDPViaQUICStream(gvisorConn, cfg, destAddr, nil)
		return true
	}
	_ = gvisorConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	firstBuf := make([]byte, 65536)
	firstN, err := gvisorConn.Read(firstBuf)
	if err != nil {
		return true
	}
	_ = gvisorConn.SetReadDeadline(time.Time{})

	conn, err := getOrDialQUICClient(cfg)
	if err != nil {
		if !IsAutoFallbackEnabled() {
			log.Printf("[QUIC-UDP] Dial failed, automatic fallback disabled: %v", err)
			return true
		}
		log.Printf("[QUIC-UDP] Dial error: %v, falling back to TCP Reality", err)
		setUDPBlocked(true)
		startUDPRecoveryProbe(cfg)
		routeUDPViaTCP(gvisorConn, cfg, destAddr, firstBuf[:firstN])
		return true
	}

	respChan := make(chan []byte, 2048)
	flowID := registerFlowSubscriber(respChan)
	defer unregisterFlowSubscriber(flowID)

	userTag := getUserTag(cfg.User)
	destBytes := []byte(destAddr)
	sendDgram := func(payload []byte) error {
		// [4B userTag][4B flowID][2B destLen][destAddr][payload]
		pkt := make([]byte, 4+4+2+len(destBytes)+len(payload))
		copy(pkt[:4], userTag[:])
		binary.BigEndian.PutUint32(pkt[4:8], flowID)
		binary.BigEndian.PutUint16(pkt[8:10], uint16(len(destBytes)))
		copy(pkt[10:10+len(destBytes)], destBytes)
		copy(pkt[10+len(destBytes):], payload)
		quicPacer.Pace(len(pkt))
		return conn.SendDatagram(pkt)
	}

	if err := sendDgram(firstBuf[:firstN]); err != nil {
		if isQUICDatagramTooLarge(err) {
			log.Printf("[QUIC-UDP] Packet exceeds DATAGRAM limit, using QUIC stream")
			routeUDPViaQUICStream(gvisorConn, cfg, destAddr, firstBuf[:firstN])
			return true
		}
		if !IsAutoFallbackEnabled() {
			log.Printf("[QUIC-UDP] Send failed, automatic fallback disabled: %v", err)
			return true
		}
		log.Printf("[QUIC-UDP] SendDatagram error: %v, falling back to TCP Reality", err)
		setUDPBlocked(true)
		startUDPRecoveryProbe(cfg)
		routeUDPViaTCP(gvisorConn, cfg, destAddr, firstBuf[:firstN])
		return true
	}

	var wg sync.WaitGroup
	var closeOnce sync.Once
	done := make(chan struct{})
	closeBoth := func() {
		closeOnce.Do(func() {
			close(done)
			gvisorConn.Close()
		})
	}
	wg.Add(2)

	// gvisor -> QUIC Datagram
	go func() {
		defer wg.Done()
		defer closeBoth()
		buf := make([]byte, 65536)
		for {
			_ = gvisorConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, rErr := gvisorConn.Read(buf)
			if rErr != nil {
				return
			}
			if sErr := sendDgram(buf[:n]); sErr != nil {
				if isQUICDatagramTooLarge(sErr) {
					log.Printf("[QUIC-UDP] Flow packet exceeds DATAGRAM limit; closing instead of silently discarding every retry")
					return
				}
				if conn.Context().Err() != nil {
					return
				}
				// In UDP, transient drop/queue-full is normal under load — NEVER kill the flow!
				continue
			}
		}
	}()

	// QUIC Datagram -> gvisor
	go func() {
		defer wg.Done()
		defer closeBoth()
		for {
			select {
			case <-done:
				return
			case resp, ok := <-respChan:
				if !ok {
					return
				}
				_ = gvisorConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				written, wErr := gvisorConn.Write(resp)
				if wErr != nil || written != len(resp) {
					return
				}
			case <-time.After(60 * time.Second):
				return
			}
		}
	}()
	wg.Wait()
	return true
}

func udpStreamOptions(cfg *Config, destAddr string) wire.UDPStreamOptions {
	options := wire.UDPStreamOptions{Context: cfg.context(), ReadIdle: 300 * time.Second, WriteIdle: 10 * time.Second}
	if strings.HasSuffix(destAddr, ":53") {
		options.ReadIdle = 3 * time.Second
		options.OnResponse = learnDNSResponse
	}
	return options
}

// This is still QUIC over UDP, not a TCP fallback. The server already accepts
// packet-framed UDP on protocol 0x12. It avoids the outer DATAGRAM PMTU limit.
func routeUDPViaQUICStream(packetConn net.Conn, cfg *Config, destAddr string, initial []byte) {
	stream, err := dialQUICStream(cfg, "udp", destAddr)
	if err != nil {
		if IsAutoFallbackEnabled() {
			log.Printf("[QUIC-UDP-STREAM] Connection failed, trying REALITY/TCP: %v", err)
			routeUDPViaTCP(packetConn, cfg, destAddr, initial)
		} else {
			log.Printf("[QUIC-UDP-STREAM] Connection failed: %v", err)
		}
		return
	}
	if err := wire.RelayUDPStream(packetConn, stream, initial, udpStreamOptions(cfg, destAddr)); err != nil && cfg.context().Err() == nil {
		log.Printf("[QUIC-UDP-STREAM] Session ended: %v", err)
	}
}

func udpTCPConfig(cfg *Config, destAddr string) *Config {
	_, port, err := net.SplitHostPort(destAddr)
	if err != nil || port != "53" || cfg.Mux {
		return cfg
	}
	// Android may open many DNS source ports at once. Keep separate UDP
	// streams, but reuse one authenticated carrier instead of a TLS handshake
	// for every query. Non-DNS traffic keeps the user's transport policy.
	dns := *cfg
	dns.Mux = true
	return &dns
}

func dialUDPOverTCP(cfg *Config, destAddr string) (net.Conn, error) {
	return dialRealityTransport(udpTCPConfig(cfg, destAddr), "udp", destAddr)
}

func routeUDPViaTCP(packetConn net.Conn, cfg *Config, destAddr string, initial []byte) {
	stream, err := dialUDPOverTCP(cfg, destAddr)
	if err != nil {
		log.Printf("[UDP] Failed to connect to VPN for %s: %v", destAddr, err)
		return
	}
	if tcpConn, ok := stream.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	if err := wire.RelayUDPStream(packetConn, stream, initial, udpStreamOptions(cfg, destAddr)); err != nil && cfg.context().Err() == nil {
		log.Printf("[UDP-TCP] Session ended: %v", err)
	}
}
