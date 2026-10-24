package main

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

func isUDPBlocked() bool {
	udpBlockedMu.RLock()
	defer udpBlockedMu.RUnlock()
	return udpBlocked
}

func setUDPBlocked(b bool) {
	udpBlockedMu.Lock()
	udpBlocked = b
	udpBlockedMu.Unlock()
}

// BrutalPacer is a blocking application-level rate limiter, not congestion control.
type BrutalPacer struct {
	rateBps   uint64
	mu        sync.Mutex
	tokens    int64
	maxTokens int64
	lastCheck time.Time
}

func NewBrutalPacer(mbps uint64) *BrutalPacer {
	if mbps == 0 {
		return nil // 0 = unlimited / maximum line speed
	}
	rateBps := mbps * 1000 * 1000 / 8
	burst := int64(rateBps / 50)

	return &BrutalPacer{
		rateBps:   rateBps,
		tokens:    burst,
		maxTokens: burst,
		lastCheck: time.Now(),
	}
}

func (p *BrutalPacer) Pace(bytesSent int) {
	if p == nil || p.rateBps <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(p.lastCheck).Seconds()
	p.lastCheck = now

	p.tokens += int64(elapsed * float64(p.rateBps))
	if p.tokens > p.maxTokens {
		p.tokens = p.maxTokens
	}

	p.tokens -= int64(bytesSent)
	if p.tokens < 0 {
		deficit := -p.tokens
		sleepTime := time.Duration(float64(deficit) / float64(p.rateBps) * float64(time.Second))
		if sleepTime > 0 {
			time.Sleep(sleepTime)
		}
		p.tokens = 0
		// The wait has already repaid this debt; do not credit it again.
		p.lastCheck = time.Now()
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

var (
	quicClientConn      quicpeer.ClientConn
	quicClientTransport io.Closer
	quicClientPacket    net.PacketConn
	quicClientMu        sync.Mutex
	quicDialInProgress  bool
	quicDialWaitChan    chan struct{}
	quicDialLastErr     error
	quicDialCooldown    wire.DialCooldown
	quicFlowSeq         atomic.Uint32
	quicFlowNAT         = make(map[uint32]chan []byte)
	quicFlowNATMu       sync.RWMutex
	recoveryMu          sync.Mutex
	recoveryActive      bool
)

func registerFlowSubscriber(ch chan []byte) uint32 {
	id := quicFlowSeq.Add(1)
	if id == 0 {
		id = quicFlowSeq.Add(1)
	}
	quicFlowNATMu.Lock()
	quicFlowNAT[id] = ch
	quicFlowNATMu.Unlock()
	return id
}

func unregisterFlowSubscriber(id uint32) {
	quicFlowNATMu.Lock()
	delete(quicFlowNAT, id)
	quicFlowNATMu.Unlock()
}

func getOrDialQUICClient(cfg *Config) (_ quicpeer.ClientConn, resultErr error) {
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
		<-waitCh
		quicClientMu.Lock()
		if quicClientConn != nil {
			c := quicClientConn
			quicClientMu.Unlock()
			return c, nil
		}
		err := quicDialLastErr
		quicClientMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("quic dial completed without connection")
	}

	if err := quicDialCooldown.RetryError(time.Now()); err != nil {
		quicClientMu.Unlock()
		return nil, err
	}
	quicDialInProgress = true
	quicDialWaitChan = make(chan struct{})
	quicClientMu.Unlock()

	defer func() {
		quicClientMu.Lock()
		quicDialLastErr = resultErr
		quicDialCooldown.Record(resultErr, time.Now())
		quicDialInProgress = false
		close(quicDialWaitChan)
		quicClientMu.Unlock()
	}()

	dialTimeout := 4 * time.Second
	if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		dialTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	serverUDPAddr, err := quicpeer.ResolveUDP(ctx, cfg.ServerAddr)
	if err != nil {
		dialErr := fmt.Errorf("resolve server addr: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}

	bindIP := "0.0.0.0:0"
	if physicalLocalIP != nil {
		bindIP = net.JoinHostPort(physicalLocalIP.String(), "0")
	}
	pc, err := net.ListenPacket("udp", bindIP)
	if err != nil && bindIP != "0.0.0.0:0" {
		pc, err = net.ListenPacket("udp", "0.0.0.0:0")
	}
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
			pool, bound, err = quicadmission.FetchBoundPoolVersion(context.Background(), bootstrap, pc, byte(cfg.WireVersion))
			if err == nil {
				pc = bound
				defer bound.CloseBootstrap()
			}
		} else {
			pool, err = quicadmission.FetchPool(context.Background(), bootstrap)
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
		Conn:                  pc,
		ConnectionIDGenerator: generator,
	}

	// Synchronize SNI for QUIC with server (if empty or microsoft.com, use speed.cloudflare.com)
	quicSNI := cfg.SNI
	if quicSNI == "" || strings.Contains(strings.ToLower(quicSNI), "microsoft.com") {
		quicSNI = "speed.cloudflare.com"
	}

	tlsConfig := &tls.Config{
		ServerName:         quicSNI,
		InsecureSkipVerify: true,
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
	quicClientConn = conn
	quicClientTransport = closer
	quicClientPacket = pc
	quicDialLastErr = nil
	quicClientMu.Unlock()

	go runQUICDatagramDispatcher(conn)

	return conn, nil
}

func runQUICDatagramDispatcher(conn quicpeer.ClientConn) {
	ctx := conn.Context()
	for {
		dgram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			break
		}
		// Server -> Client: [4B flowID][2B destLen][destAddr][payload]
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
	openCtx, openCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer openCancel()
	stream, err := conn.OpenStreamSync(openCtx)
	if err != nil {
		return nil, fmt.Errorf("open quic stream sync: %w", err)
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

	var pacer *BrutalPacer
	if cfg.UpMbps > 0 {
		pacer = NewBrutalPacer(cfg.UpMbps)
	}
	return &quicNetStream{
		ClientStream: stream,
		pacer:        pacer,
		localAddr:    conn.LocalAddr(),
		remoteAddr:   conn.RemoteAddr(),
	}, nil
}

func startUDPRecoveryProbe(cfg *Config) {
	recoveryMu.Lock()
	if recoveryActive {
		recoveryMu.Unlock()
		return
	}
	recoveryActive = true
	recoveryMu.Unlock()

	go func() {
		defer func() {
			recoveryMu.Lock()
			recoveryActive = false
			recoveryMu.Unlock()
		}()

		for i := 0; i < 30; i++ {
			time.Sleep(10 * time.Second)
			if !isUDPBlocked() {
				return
			}
			// Принудительно сбрасываем старый коннект, чтобы проверить реальное прохождение QUIC Handshake
			quicClientMu.Lock()
			if quicClientConn != nil {
				_ = quicClientConn.CloseWithError(0, "recovery probe")
				quicClientConn = nil
			}
			if quicClientTransport != nil {
				_ = quicClientTransport.Close()
				quicClientTransport = nil
			}
			if quicClientPacket != nil {
				_ = quicClientPacket.Close()
				quicClientPacket = nil
			}
			quicClientMu.Unlock()

			if _, err := getOrDialQUICClient(cfg); err == nil {
				log.Printf("[UDP-RECOVERY] UDP handshake verified, switching back to QUIC UDP tunnel")
				setUDPBlocked(false)
				return
			}
		}
	}()
}

func handleUDPViaDatagramTunnel(gvisorConn net.Conn, cfg *Config, destAddr string) bool {
	_ = gvisorConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	firstBuf := make([]byte, 1500)
	firstN, err := gvisorConn.Read(firstBuf)
	if err != nil {
		return true
	}
	_ = gvisorConn.SetReadDeadline(time.Time{})

	conn, err := getOrDialQUICClient(cfg)
	if err != nil {
		log.Printf("[QUIC-UDP] Server connection failed: %v, falling back to TCP Reality", err)
		routeUDPViaTCP(gvisorConn, cfg, destAddr, firstBuf[:firstN])
		return false
	}

	respChan := make(chan []byte, 2048)
	flowID := registerFlowSubscriber(respChan)
	defer unregisterFlowSubscriber(flowID)

	userTag := getUserTag(cfg.User)
	destBytes := []byte(destAddr)
	var dgramPacer *BrutalPacer
	if cfg.UpMbps > 0 {
		dgramPacer = NewBrutalPacer(cfg.UpMbps)
	}
	sendDgram := func(payload []byte) error {
		// [4B userTag][4B flowID][2B destLen][destAddr][payload]
		pkt := make([]byte, 4+4+2+len(destBytes)+len(payload))
		copy(pkt[:4], userTag[:])
		binary.BigEndian.PutUint32(pkt[4:8], flowID)
		binary.BigEndian.PutUint16(pkt[8:10], uint16(len(destBytes)))
		copy(pkt[10:10+len(destBytes)], destBytes)
		copy(pkt[10+len(destBytes):], payload)
		if dgramPacer != nil {
			dgramPacer.Pace(len(pkt))
		}
		return conn.SendDatagram(pkt)
	}

	if err := sendDgram(firstBuf[:firstN]); err != nil {
		routeUDPViaTCP(gvisorConn, cfg, destAddr, firstBuf[:firstN])
		return false
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
		buf := make([]byte, 1500)
		for {
			_ = gvisorConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, rErr := gvisorConn.Read(buf)
			if rErr != nil {
				return
			}
			if sErr := sendDgram(buf[:n]); sErr != nil {
				if conn.Context().Err() != nil {
					return
				}
				// In UDP, transient drop or MTU excess is normal — NEVER kill the session
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
				if strings.HasSuffix(destAddr, ":53") {
					learnDNSResponse(resp)
				}
				if _, wErr := gvisorConn.Write(resp); wErr != nil {
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

// routeUDPViaTCPDirect delegates directly to routeUDPViaTCP, respecting cfg.TCPProto (xhttp or reality).
func routeUDPViaTCPDirect(gvisorConn net.Conn, cfg *Config, destAddr string, initialPacket []byte) {
	routeUDPViaTCP(gvisorConn, cfg, destAddr, initialPacket)
}

func routeUDPViaTCP(gvisorConn net.Conn, cfg *Config, destAddr string, initialPacket []byte) {
	log.Printf("[UDP-TCP] Route via TCP Reality stream to %s (initial_len=%d)", destAddr, len(initialPacket))
	var remoteConn net.Conn
	var err error
	if strings.ToLower(cfg.TCPProto) == "xhttp" {
		remoteConn, err = dialXHTTPStream(cfg, "udp", destAddr)
	} else {
		remoteConn, err = dialRemoteRealityStream(cfg, "udp", destAddr)
	}
	if err != nil {
		log.Printf("[UDP] Failed to connect to VPN for %s: %v", destAddr, err)
		return
	}
	defer remoteConn.Close()

	if len(initialPacket) > 65535 {
		log.Printf("[UDP] Initial packet exceeds framing limit: %d", len(initialPacket))
		return
	}
	if initialPacket != nil {
		lenHdr := make([]byte, 2)
		binary.BigEndian.PutUint16(lenHdr, uint16(len(initialPacket)))
		_ = remoteConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := writeFull(remoteConn, append(lenHdr, initialPacket...))
		_ = remoteConn.SetWriteDeadline(time.Time{})
		if err != nil {
			log.Printf("[UDP] Failed to send initialPacket to TCP: %v", err)
			return
		}
	}

	readTimeout := 300 * time.Second
	if strings.HasSuffix(destAddr, ":53") {
		readTimeout = 3 * time.Second
	}

	var wg sync.WaitGroup
	var once sync.Once
	closeBoth := func() { _ = remoteConn.Close(); _ = gvisorConn.Close() }
	wg.Add(2)

	// gvisor -> remote (length-prefixed)
	go func() {
		defer wg.Done()
		defer once.Do(closeBoth)
		buf := make([]byte, 2+65535)
		for {
			_ = gvisorConn.SetReadDeadline(time.Now().Add(readTimeout))
			n, err := gvisorConn.Read(buf[2:])
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			_ = remoteConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			wErr := writeFull(remoteConn, buf[:2+n])
			_ = remoteConn.SetWriteDeadline(time.Time{})
			if wErr != nil {
				return
			}
		}
	}()

	// remote -> gvisor (length-prefixed)
	go func() {
		defer wg.Done()
		defer once.Do(closeBoth)
		lenBuf := make([]byte, 2)
		for {
			_ = remoteConn.SetReadDeadline(time.Now().Add(readTimeout))
			if _, err := io.ReadFull(remoteConn, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			buf := make([]byte, length)
			if _, err := io.ReadFull(remoteConn, buf); err != nil {
				return
			}
			if strings.HasSuffix(destAddr, ":53") {
				learnDNSResponse(buf)
			}
			_ = gvisorConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, gwErr := gvisorConn.Write(buf)
			_ = gvisorConn.SetWriteDeadline(time.Time{})
			if gwErr != nil {
				return
			}
		}
	}()
	wg.Wait()
}
