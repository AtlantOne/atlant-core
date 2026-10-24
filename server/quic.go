package main

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/quicreality"
	"atlant.local/protocol/wire"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

// BrutalPacer is a blocking application-level rate limiter, not congestion control.
type BrutalPacer struct {
	rateBps   int64
	mu        sync.Mutex
	tokens    int64
	maxTokens int64
	lastCheck time.Time
}

func NewBrutalPacer(rateMbps uint64) *BrutalPacer {
	if rateMbps == 0 {
		// 0 represents unlimited speed / line rate (no artificial pacing)
		return nil
	}
	rateBps := int64(rateMbps * 1000 * 1000 / 8)
	burst := rateBps / 50 // 20ms burst quantum

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

type serverConnIDGenerator struct{ demux *DemuxPacketConn }

func (g *serverConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	if g.demux == nil {
		return quic.ConnectionID{}, fmt.Errorf("QUIC CID generator has no listener")
	}
	var cid [16]byte
	if _, err := rand.Read(cid[:]); err != nil {
		return quic.ConnectionID{}, err
	}
	cidKey := string(cid[:])
	g.demux.authCIDs.Set(cidKey, time.Now())
	return quic.ConnectionIDFromBytes(cid[:]), nil
}

func (g *serverConnIDGenerator) ConnectionIDLen() int {
	return 16
}

// startUDPVPNServer starts the QUIC listener and optional upload rate limiter.
func startUDPVPNServer(listenAddr string) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Printf("[QUIC-HYSTERIA] Failed to start UDP packet listener on %s: %v", listenAddr, err)
		return
	}
	if err := serveUDPVPNServer(context.Background(), pc, cfg, serverStaticECDH); err != nil {
		log.Printf("[QUIC-REALITY] UDP listener on %s stopped: %v", listenAddr, err)
	}
}

// Each listener receives its own immutable settings and identity; user storage
// and accounting remain shared by the process. Closing the context stops its
// accept loop and transport without stopping other listeners.
func serveUDPVPNServer(ctx context.Context, pc net.PacketConn, cfg *Config, identity *ecdh.PrivateKey) error {
	return serveUDPVPNServerReady(ctx, pc, cfg, identity, nil)
}

func serveUDPVPNServerReady(ctx context.Context, pc net.PacketConn, cfg *Config, identity *ecdh.PrivateKey, ready func()) error {
	defer pc.Close()

	// Expand socket buffers
	sockBufSize := cfg.GetQuicSocketBufferSize()
	if uConn, ok := pc.(*net.UDPConn); ok {
		_ = uConn.SetReadBuffer(sockBufSize)
		_ = uConn.SetWriteBuffer(sockBufSize)
	}

	quicSNI := cfg.GetSNI()
	if quicSNI == "" || strings.Contains(strings.ToLower(quicSNI), "microsoft.com") {
		// Use genuine HTTP/3 donor on UDP:443
		quicSNI = "speed.cloudflare.com"
	}
	serverObfKey := getServerObfKey(quicSNI)
	if cfg.WireVersion != 7 {
		initServerKeys(quicSNI)
	}

	var direct *directQUICGate
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cfg.WireVersion == 7 {
				admission, err := directAdmission(info.Context())
				if err != nil {
					return nil, err
				}
				cert, err := quicreality.Certificate(quicSNI, *admission)
				return &cert, err
			}
			cert := getQUICTLS13Cert(quicSNI)
			return &cert, nil
		},
		NextProtos: []string{"h3"},
	}
	quicpeer.ConfigureTLSPrivacy(tlsConfig, cfg.WireVersion)

	quicConfig := inboundQUICConfig(cfg)

	donorUDP := quicSNI + ":443"
	gate := activeAdmission.Load()
	if cfg.WireVersion == 7 {
		gate = nil
	}
	if gate != nil {
		quicConfig.Tracer = gate.tracer
	}
	demuxConn, err := newDemuxPacketConnContext(ctx, pc, serverObfKey, donorUDP, cfg.WireVersion, cfg.LegacyWire, gate, identity, cfg.InboundID)
	if err != nil {
		return fmt.Errorf("initialize QUIC admission: %w", err)
	} else {
		log.Printf("[QUIC-REALITY] CID admission and decoy forwarding enabled (donor: %s)", donorUDP)
	}
	if demuxConn != nil {
		direct = demuxConn.direct
	}
	if direct != nil {
		quicConfig.Tracer = direct.tracer
	}

	packetSource := net.PacketConn(pc)
	if demuxConn != nil {
		packetSource = demuxConn
		defer demuxConn.Close()
	}

	tr := &quic.Transport{
		Conn:                  packetSource,
		ConnectionIDGenerator: &serverConnIDGenerator{demux: demuxConn},
	}
	var sessions sync.WaitGroup
	var sessionMu sync.Mutex
	sessionConns := make(map[*quic.Conn]struct{})
	defer func() {
		sessionMu.Lock()
		peers := make([]*quic.Conn, 0, len(sessionConns))
		for conn := range sessionConns {
			peers = append(peers, conn)
		}
		sessionMu.Unlock()
		for _, conn := range peers {
			_ = conn.CloseWithError(0, "listener stopped")
		}
		_ = tr.Close()
		sessions.Wait()
	}()
	if direct != nil {
		tr.ConnContext = direct.connContext
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	if gate != nil {
		tr.ConnContext = gate.connContext
		if cfg.WireVersion == 6 {
			tr.VerifySourceAddress = func(net.Addr) bool { return true }
		}
	}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("start QUIC listener: %w", err)
	}
	defer listener.Close()

	upLimit := cfg.GetUpMbps()
	pacerDesc := "Unlimited (Line Rate)"
	if !cfg.Quic.DisablePacer && upLimit > 0 {
		pacerDesc = fmt.Sprintf("%d Mbps (application rate limit)", upLimit)
	}
	log.Printf("[QUIC-REALITY] QUIC-Reality Core running on UDP %s (Decoy: %s, Speed limit: %s)", pc.LocalAddr(), donorUDP, pacerDesc)
	if ready != nil {
		ready()
	}

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if strings.Contains(err.Error(), "closed") {
				return err
			}
			continue
		}
		var sessionPacer *BrutalPacer
		if !cfg.Quic.DisablePacer && upLimit > 0 {
			sessionPacer = NewBrutalPacer(upLimit)
		}
		sessionMu.Lock()
		sessionConns[conn] = struct{}{}
		sessionMu.Unlock()
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { sessionMu.Lock(); delete(sessionConns, conn); sessionMu.Unlock() }()
			handleQUICSession(conn, sessionPacer)
		}()
	}
}

func handleQUICSession(conn *quic.Conn, pacer *BrutalPacer) {
	defer conn.CloseWithError(0, "session closed")
	ctx, cancel := context.WithCancel(conn.Context())
	defer cancel()

	clientAddrStr := conn.RemoteAddr().String()
	authCtx, authCancel := context.WithTimeout(ctx, 5*time.Second)
	boundUser, authErr := quicpeer.Server(authCtx, conn, func(name string) ([]byte, bool) {
		if !isUserAllowed(name) {
			return nil, false
		}
		usersMu.RLock()
		rec := usersDB.Users[name]
		var secret string
		if rec != nil {
			secret = rec.PBK
		}
		usersMu.RUnlock()
		if secret == "" {
			return nil, false
		}
		return parsePBKBytes(secret), true
	})
	authCancel()
	if authErr == nil {
		authErr = commitAdmission(conn, boundUser)
	}
	if authErr != nil {
		_ = conn.CloseWithError(0x100, "peer authentication failed")
		return
	}
	if !isUserAllowed(boundUser) {
		log.Printf("[SECURITY] Bound user '%s' blocked or traffic limit reached on QUIC from %s", boundUser, clientAddrStr)
		_ = conn.CloseWithError(0x01, "user limit reached")
		return
	}
	cleanup, sessionErr := reserveUserSession(boundUser, clientAddrStr, func() {
		_ = conn.CloseWithError(0, "kicked")
	})
	if sessionErr != nil {
		_ = conn.CloseWithError(1, "session rejected")
		return
	}
	defer cleanup()
	if ref, _ := conn.Context().Value(directContextKey{}).(*directContext); ref != nil && !inboundUserAllowed(ref.gate.inboundID, boundUser) {
		return
	}
	log.Printf("[QUIC-SESSION] Established session for authenticated user '%s' from %s", boundUser, clientAddrStr)

	// TCP VPN streams
	go func() {
		for {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				break
			}
			go handleQUICStream(stream, pacer, boundUser, conn.RemoteAddr().String())
		}
	}()

	// UDP datagrams (RFC 9221)
	type dgramNATEntry struct {
		destConn       *net.UDPConn
		destAddr       string
		lastActiveUnix int64
	}
	var natMu sync.Mutex
	natMap := make(map[string]*dgramNATEntry)

	defer func() {
		natMu.Lock()
		for _, e := range natMap {
			e.destConn.Close()
		}
		natMap = nil
		natMu.Unlock()
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			natMu.Lock()
			nowSec := time.Now().Unix()
			for k, e := range natMap {
				if nowSec-atomic.LoadInt64(&e.lastActiveUnix) > 60 {
					e.destConn.Close()
					delete(natMap, k)
				}
			}
			natMu.Unlock()
		}
	}()

	for {
		dgram, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			break
		}
		if len(dgram) < 10 {
			continue
		}
		expectedTag := getUserTag(boundUser)
		if !hmac.Equal(dgram[:4], expectedTag[:]) {
			continue
		}
		// [4B userTag][4B flowID][2B destLen][destAddr][payload]
		flowID := binary.BigEndian.Uint32(dgram[4:8])
		destLen := int(binary.BigEndian.Uint16(dgram[8:10]))
		if destLen < 1 || destLen > 512 || len(dgram) < 10+destLen {
			continue
		}
		destAddr := string(dgram[10 : 10+destLen])
		payload := dgram[10+destLen:]

		natKey := fmt.Sprintf("%d-%s", flowID, destAddr)

		natMu.Lock()
		entry, exists := natMap[natKey]
		if !exists {
			// Pool size limit (max 1024 sockets) with LRU eviction
			if len(natMap) >= 1024 {
				var oldestKey string
				var oldestSec int64
				first := true
				for k, e := range natMap {
					t := atomic.LoadInt64(&e.lastActiveUnix)
					if first || t < oldestSec {
						oldestSec = t
						oldestKey = k
						first = false
					}
				}
				if oldestKey != "" {
					natMap[oldestKey].destConn.Close()
					delete(natMap, oldestKey)
				}
			}
			rAddr, rErr := safeResolveUDP(destAddr)
			if rErr != nil {
				natMu.Unlock()
				log.Printf("[QUIC-DGRAM] Blocked or unresolvable UDP destination %s: %v", destAddr, rErr)
				continue
			}
			dConn, dErr := net.DialUDP("udp", nil, rAddr)
			if dErr != nil {
				natMu.Unlock()
				continue
			}
			_ = dConn.SetReadBuffer(256 * 1024)
			_ = dConn.SetWriteBuffer(256 * 1024)
			entry = &dgramNATEntry{
				destConn:       dConn,
				destAddr:       destAddr,
				lastActiveUnix: time.Now().Unix(),
			}
			natMap[natKey] = entry

			go func(e *dgramNATEntry, target string, fID uint32) {
				defer func() {
					natMu.Lock()
					if natMap[natKey] == e {
						delete(natMap, natKey)
					}
					natMu.Unlock()
					_ = e.destConn.Close()
				}()
				rBuf := make([]byte, 65536)
				destBytes := []byte(target)
				prefixLen := 4 + 2 + len(destBytes)
				for {
					if ctx.Err() != nil {
						break
					}
					_ = e.destConn.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, err := e.destConn.Read(rBuf)
					if err != nil {
						break
					}
					if ctx.Err() != nil {
						break
					}
					atomic.StoreInt64(&e.lastActiveUnix, time.Now().Unix())

					response := dnsUDPResponse(target, rBuf[:rn])
					rn = len(response)
					respPkt := make([]byte, prefixLen+rn)
					binary.BigEndian.PutUint32(respPkt[:4], fID)
					binary.BigEndian.PutUint16(respPkt[4:6], uint16(len(destBytes)))
					copy(respPkt[6:prefixLen], destBytes)
					copy(respPkt[prefixLen:], response)

					if !recordUserTraffic(boundUser, 0, uint64(len(respPkt))) {
						return
					}

					if pacer != nil {
						pacer.Pace(len(respPkt))
					}
					if sErr := conn.SendDatagram(respPkt); sErr != nil {
						continue
					}
				}
			}(entry, destAddr, flowID)
		} else {
			atomic.StoreInt64(&entry.lastActiveUnix, time.Now().Unix())
		}
		natMu.Unlock()

		if !recordUserTraffic(boundUser, uint64(len(payload)), 0) {
			return
		}
		_ = entry.destConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = entry.destConn.Write(payload)
	}
}

func handleQUICStream(stream *quic.Stream, pacer *BrutalPacer, boundUser string, clientRemoteAddr string) {
	defer stream.Close()
	defer stream.CancelRead(0)
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	cleanup, sessionErr := reserveUserSession(boundUser, clientRemoteAddr, func() {
		stream.CancelRead(0x101)
		stream.CancelWrite(0x101)
	})
	if sessionErr != nil {
		return
	}
	defer cleanup()

	if boundUser == "" || !isUserAllowed(boundUser) {
		return
	}
	header, err := wire.ReadQUICHeader(stream)
	if err != nil {
		return
	}
	expectedTag := getUserTag(boundUser)
	if !hmac.Equal(header.UserTag[:], expectedTag[:]) {
		return
	}
	protoByte, destAddr := header.Protocol, header.Destination
	_ = stream.SetReadDeadline(time.Time{})

	if protoByte == 0x12 || protoByte == 0x02 {
		udpAddr, err := safeResolveUDP(destAddr)
		if err != nil {
			log.Printf("[QUIC-STREAM-UDP] Failed to resolve %s: %v", destAddr, err)
			return
		}
		uConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Printf("[QUIC-STREAM-UDP] Failed to dial %s: %v", destAddr, err)
			return
		}
		defer uConn.Close()

		var wg sync.WaitGroup
		var once sync.Once
		closeUDPRelay := func() {
			once.Do(func() {
				_ = uConn.Close()
				stream.CancelRead(0)
				_ = stream.Close()
			})
		}
		wg.Add(2)

		go func() {
			defer wg.Done()
			defer closeUDPRelay()
			var lenBuf [2]byte
			buf := make([]byte, 65507)
			for {
				_ = stream.SetReadDeadline(time.Now().Add(60 * time.Second))
				if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
					return
				}
				length := binary.BigEndian.Uint16(lenBuf[:])
				if length > 65507 {
					return
				}
				if _, err := io.ReadFull(stream, buf[:length]); err != nil {
					return
				}
				if !recordUserTraffic(boundUser, uint64(length), 0) {
					return
				}
				_ = uConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := uConn.Write(buf[:length]); err != nil {
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			defer closeUDPRelay()
			buf := make([]byte, 2+65507)
			for {
				_ = uConn.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, err := uConn.Read(buf[2:])
				if err != nil {
					return
				}
				response := dnsUDPResponse(destAddr, buf[2:2+n])
				n = copy(buf[2:], response)
				if !recordUserTraffic(boundUser, 0, uint64(n)) {
					return
				}
				binary.BigEndian.PutUint16(buf[:2], uint16(n))
				if pacer != nil {
					pacer.Pace(2 + n)
				}
				_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := writeFull(stream, buf[:2+n]); err != nil {
					return
				}
			}
		}()

		wg.Wait()
		return
	}

	if isSpeedtestAddr(destAddr) {
		handleSpeedtestStream(stream, boundUser)
		return
	}

	destConn, err := safeDialTCP(destAddr, 10*time.Second)
	if err != nil {
		log.Printf("[QUIC-STREAM] Dial failed or SSRF blocked for %s: %v", destAddr, err)
		return
	}
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = destConn.Close()
			stream.CancelRead(0)
			_ = stream.Close()
		})
	}
	defer closeBoth()

	var wg sync.WaitGroup
	wg.Add(2)

	// Uplink: client stream -> destConn
	go func() {
		defer wg.Done()
		buf := make([]byte, 32768)
		var readIdle, writeIdle wire.IdleDeadline
		for {
			_ = readIdle.Update(time.Now(), 120*time.Second, stream.SetReadDeadline)
			n, rErr := stream.Read(buf)
			if n > 0 {
				if !recordUserTraffic(boundUser, uint64(n), 0) {
					closeBoth()
					return
				}
				_ = writeIdle.Update(time.Now(), 30*time.Second, destConn.SetWriteDeadline)
				if wErr := writeFull(destConn, buf[:n]); wErr != nil {
					closeBoth()
					break
				}
			}
			if rErr != nil {
				// Proper TCP half-close: inform remote server that client finished sending
				if tcpConn, ok := destConn.(*net.TCPConn); ok {
					_ = tcpConn.CloseWrite()
				}
				break
			}
		}
	}()

	// Downlink: destConn -> client stream
	go func() {
		defer wg.Done()
		defer closeBoth()
		buf := make([]byte, 32768)
		var readIdle, writeIdle wire.IdleDeadline
		for {
			_ = readIdle.Update(time.Now(), 120*time.Second, destConn.SetReadDeadline)
			n, rErr := destConn.Read(buf)
			if n > 0 {
				if !recordUserTraffic(boundUser, 0, uint64(n)) {
					return
				}
				if pacer != nil {
					pacer.Pace(n)
				}
				_ = writeIdle.Update(time.Now(), 30*time.Second, stream.SetWriteDeadline)
				if wErr := writeFull(stream, buf[:n]); wErr != nil {
					break
				}
			}
			if rErr != nil {
				break
			}
		}
	}()

	wg.Wait()
}
