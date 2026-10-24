package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

func handleXHTTP(conn net.Conn) {
	handleXHTTPConfigured(conn, cfg)
}

func handleXHTTPConfigured(conn net.Conn, cfg *Config) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		log.Printf("[XHTTP] Real cert/key not configured, closing connection")
		conn.Close()
		return
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Printf("[XHTTP] Failed to load cert/key files: %v", err)
		conn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   cfg.GetSNI(),
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[XHTTP] TLS handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	tlsConn.SetDeadline(time.Time{})
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol == "h2" {
		log.Printf("[XHTTP] HTTP/2 connection negotiated with %s", conn.RemoteAddr())
		handleXHTTPServerForPath(tlsConn, cfg.Path, true)
	} else {
		log.Printf("[XHTTP] Connection from %s negotiated %s instead of h2", conn.RemoteAddr(), state.NegotiatedProtocol)
	}
}

func authenticateBearerToken(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	tokenHash := sha256.Sum256([]byte(token))

	usersMu.RLock()
	defer usersMu.RUnlock()

	var matchedUser string
	var matched bool
	nowUnix := time.Now().Unix()
	for name, user := range usersDB.Users {
		if user == nil || user.PBK == "" || !user.Enabled {
			continue
		}
		if user.ExpiresAt > 0 && nowUnix > user.ExpiresAt {
			continue
		}
		pbkHash := sha256.Sum256([]byte(user.PBK))
		if subtle.ConstantTimeCompare(tokenHash[:], pbkHash[:]) == 1 {
			matchedUser = name
			matched = true
		}
		userWithPBKHash := sha256.Sum256([]byte(name + ":" + user.PBK))
		if subtle.ConstantTimeCompare(tokenHash[:], userWithPBKHash[:]) == 1 {
			matchedUser = name
			matched = true
		}
	}
	return matchedUser, matched
}

func authenticateAuthHash(hash []byte) (string, bool) {
	if len(hash) != 32 {
		return "", false
	}
	usersMu.RLock()
	defer usersMu.RUnlock()

	nowUnix := time.Now().Unix()
	for name, user := range usersDB.Users {
		if user == nil || user.PBK == "" || !user.Enabled {
			continue
		}
		if user.ExpiresAt > 0 && nowUnix > user.ExpiresAt {
			continue
		}
		// Direct SHA256 of user.PBK string
		pbkHash := sha256.Sum256([]byte(user.PBK))
		if subtle.ConstantTimeCompare(hash, pbkHash[:]) == 1 {
			return name, true
		}
		// SHA256 of name:user.PBK string
		userWithPBKHash := sha256.Sum256([]byte(name + ":" + user.PBK))
		if subtle.ConstantTimeCompare(hash, userWithPBKHash[:]) == 1 {
			return name, true
		}
		// Raw 32-byte decoded hex of PBK
		if hexBytes, err := hex.DecodeString(user.PBK); err == nil && len(hexBytes) == 32 {
			if subtle.ConstantTimeCompare(hash, hexBytes) == 1 {
				return name, true
			}
		}
	}
	return "", false
}

func authenticateHMAC(data, sig []byte) (string, bool) {
	if len(sig) != 32 {
		return "", false
	}
	usersMu.RLock()
	defer usersMu.RUnlock()

	nowUnix := time.Now().Unix()
	for name, user := range usersDB.Users {
		if user == nil || user.PBK == "" || !user.Enabled {
			continue
		}
		if user.ExpiresAt > 0 && nowUnix > user.ExpiresAt {
			continue
		}
		key := []byte(user.PBK)
		if hexBytes, err := hex.DecodeString(user.PBK); err == nil && len(hexBytes) == 32 {
			key = hexBytes
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		expected := mac.Sum(nil)
		if subtle.ConstantTimeCompare(sig, expected) == 1 {
			return name, true
		}
	}
	return "", false
}

var (
	xhttpReplayMu       sync.Mutex
	xhttpUsedTokens     = make(map[string]int64)
	xhttpLastCleanupSec int64
)

func checkAndRecordXHTTPReplay(token string, now int64) bool {
	xhttpReplayMu.Lock()
	defer xhttpReplayMu.Unlock()
	// Periodic cleanup throttled to at most once per 60 seconds
	if now-xhttpLastCleanupSec > 60 || len(xhttpUsedTokens) > 20000 {
		xhttpLastCleanupSec = now
		for k, t := range xhttpUsedTokens {
			if now-t > 360 {
				delete(xhttpUsedTokens, k)
			}
		}
	}
	if _, exists := xhttpUsedTokens[token]; exists {
		return false
	}
	if len(xhttpUsedTokens) >= 20000 {
		return false
	}
	xhttpUsedTokens[token] = now
	return true
}

func parseStealthPreamble(r io.Reader) (user, dest, proto string, err error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", "", "", err
	}
	if header[0] != 0xA1 || (header[1] != 0x01 && header[1] != 0x02) {
		return "", "", "", fmt.Errorf("invalid xhttp preamble magic: 0x%02x 0x%02x", header[0], header[1])
	}

	var matchedUser string
	if header[1] == 0x02 {
		var tsNonce [16]byte
		if _, err := io.ReadFull(r, tsNonce[:]); err != nil {
			return "", "", "", err
		}
		var hmacSig [32]byte
		if _, err := io.ReadFull(r, hmacSig[:]); err != nil {
			return "", "", "", err
		}
		clientTime := int64(binary.BigEndian.Uint64(tsNonce[:8]))
		now := time.Now().Unix()
		diff := now - clientTime
		if diff < -180 || diff > 180 {
			return "", "", "", fmt.Errorf("xhttp v2 preamble timestamp expired (drift=%ds)", diff)
		}
		u, ok := authenticateHMAC(tsNonce[:], hmacSig[:])
		if !ok {
			return "", "", "", fmt.Errorf("xhttp v2 preamble auth failed")
		}
		if !checkAndRecordXHTTPReplay(u+":"+string(tsNonce[:]), now) {
			return "", "", "", fmt.Errorf("xhttp replay rejected or replay cache full")
		}
		matchedUser = u
	} else {
		var authHash [32]byte
		if _, err := io.ReadFull(r, authHash[:]); err != nil {
			return "", "", "", err
		}
		u, ok := authenticateAuthHash(authHash[:])
		if !ok {
			return "", "", "", fmt.Errorf("preamble auth failed")
		}
		matchedUser = u
	}

	var meta [3]byte
	if _, err := io.ReadFull(r, meta[:]); err != nil {
		return "", "", "", err
	}
	switch meta[0] {
	case 0x02:
		proto = "udp"
	default:
		proto = "tcp"
	}
	port := binary.BigEndian.Uint16(meta[1:3])

	var addrType [1]byte
	if _, err := io.ReadFull(r, addrType[:]); err != nil {
		return "", "", "", err
	}

	var host string
	switch addrType[0] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", "", "", err
		}
		host = net.IP(ip[:]).String()
	case 0x02: // Domain
		var dLen [1]byte
		if _, err := io.ReadFull(r, dLen[:]); err != nil {
			return "", "", "", err
		}
		domainBuf := make([]byte, dLen[0])
		if _, err := io.ReadFull(r, domainBuf); err != nil {
			return "", "", "", err
		}
		host = string(domainBuf)
	case 0x03: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return "", "", "", err
		}
		host = fmt.Sprintf("[%s]", net.IP(ip[:]).String())
	default:
		return "", "", "", fmt.Errorf("unsupported addr type: 0x%02x", addrType[0])
	}
	dest = fmt.Sprintf("%s:%d", host, port)

	// Random Padding
	var padLenBuf [2]byte
	if _, err := io.ReadFull(r, padLenBuf[:]); err != nil {
		return "", "", "", err
	}
	padLen := int(binary.BigEndian.Uint16(padLenBuf[:]))
	if padLen > 0 {
		if padLen > 2048 {
			return "", "", "", fmt.Errorf("padding length too large: %d", padLen)
		}
		padBuf := make([]byte, padLen)
		if _, err := io.ReadFull(r, padBuf); err != nil {
			return "", "", "", err
		}
	}

	return matchedUser, dest, proto, nil
}

func randomHex(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// http2DuplexConn implements net.Conn over incoming and outgoing HTTP/2 streams.
type http2DuplexConn struct {
	reader     io.ReadCloser
	writer     io.Writer
	flusher    http.Flusher
	closer     io.Closer
	remoteAddr net.Addr
	localAddr  net.Addr
	closeOnce  sync.Once
	closed     chan struct{}
	controller *http.ResponseController
}

func newServerDuplexConn(r *http.Request, w http.ResponseWriter, flusher http.Flusher) *http2DuplexConn {
	remoteTCP, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	return &http2DuplexConn{
		reader:     r.Body,
		writer:     w,
		flusher:    flusher,
		closer:     r.Body,
		remoteAddr: remoteTCP,
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
		closed:     make(chan struct{}),
		controller: http.NewResponseController(w),
	}
}

func (c *http2DuplexConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *http2DuplexConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	// The HTTP/2 implementation splits DATA at the negotiated frame size.
	// Bound each application write, not each HTTP/2 frame; never wait to fill it.
	const maxFrame = 64 * 1024
	total := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > maxFrame {
			chunkSize = maxFrame
		}
		n, err := c.writer.Write(b[:chunkSize])
		if n < 0 || n > chunkSize {
			return total, io.ErrShortWrite
		}
		if n > 0 {
			total += n
			if c.flusher != nil {
				c.flusher.Flush()
			}
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}

func (c *http2DuplexConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.closer != nil {
			c.closer.Close()
		}
	})
	return nil
}

func (c *http2DuplexConn) CloseWrite() error {
	if closer, ok := c.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (c *http2DuplexConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *http2DuplexConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *http2DuplexConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *http2DuplexConn) SetReadDeadline(t time.Time) error {
	if c.controller == nil {
		return http.ErrNotSupported
	}
	return c.controller.SetReadDeadline(t)
}
func (c *http2DuplexConn) SetWriteDeadline(t time.Time) error {
	if c.controller == nil {
		return http.ErrNotSupported
	}
	return c.controller.SetWriteDeadline(t)
}

func serveFallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n"))
}

func handleXHTTPServer(tlsConn net.Conn) {
	handleXHTTPServerForPath(tlsConn, cfg.Path, true)
}

func handleXHTTPServerForPath(tlsConn net.Conn, path string, legacyPath bool) {
	handleBoundXHTTPServer(tlsConn, path, legacyPath, "", "")
}

func handleBoundXHTTPServer(tlsConn net.Conn, path string, legacyPath bool, outerUser, inboundID string) {
	defer tlsConn.Close()
	targetPath := strings.TrimRight(path, "/")
	if path == "" {
		targetPath = "/api/v1/sync"
	} else if targetPath == "" {
		targetPath = "/"
	}
	if conn, ok := tlsConn.(interface{ enableXHTTPBatching() }); ok {
		conn.enableXHTTPBatching()
	}

	h2Server := &http2.Server{
		MaxConcurrentStreams: 250,
		MaxReadFrameSize:     16384,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return
		}
		reqPath := strings.TrimRight(r.URL.Path, "/")
		if reqPath == "" {
			reqPath = "/"
		}

		// Fallback on path/method mismatch
		if (reqPath != targetPath && !(legacyPath && reqPath == "/api/v1/sync")) || r.Method != http.MethodPost {
			log.Printf("[XHTTP] Censor/probe fallback for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
			serveFallback(w, r)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming not supported", http.StatusInternalServerError)
			return
		}

		var dest, proto, user string
		var authenticated bool

		legacyDest := r.Header.Get("X-Dest")
		if legacyDest != "" {
			// Legacy headers compatibility
			authHeader := r.Header.Get("Authorization")
			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			user, authenticated = authenticateBearerToken(token)
			if !authenticated {
				if xUser := r.Header.Get("X-User"); xUser != "" {
					usersMu.RLock()
					if uRec, uExists := usersDB.Users[xUser]; uExists && uRec != nil && uRec.Enabled {
						if uRec.PBK == token || token == (xUser+":"+uRec.PBK) {
							user = xUser
							authenticated = true
						}
					}
					usersMu.RUnlock()
				}
			}
			dest = legacyDest
			proto = strings.ToLower(r.Header.Get("X-Proto"))
			if proto == "" {
				proto = "tcp"
			}
		} else {
			// Stealth Preamble (XHTTP v2)
			var pErr error
			user, dest, proto, pErr = parseStealthPreamble(r.Body)
			if pErr != nil {
				log.Printf("[XHTTP] Stealth preamble invalid/unauthorized from %s: %v", r.RemoteAddr, pErr)
				serveFallback(w, r)
				return
			}
			authenticated = true
		}

		if !authenticated || dest == "" {
			log.Printf("[XHTTP] Unauthorized XHTTP request from %s", r.RemoteAddr)
			serveFallback(w, r)
			return
		}

		if !isUserAllowed(user) || (outerUser != "" && (user != outerUser || !inboundUserAllowed(inboundID, user))) {
			log.Printf("[SECURITY] User '%s' blocked or traffic limit reached on XHTTP from %s", user, r.RemoteAddr)
			serveFallback(w, r)
			return
		}
		var targets revocableTarget
		closeStream := func() {
			_ = targets.Close()
			_ = controller.SetReadDeadline(time.Now())
			_ = controller.SetWriteDeadline(time.Now())
			_ = r.Body.Close()
		}
		cleanup, err := reserveUserSession(user, r.RemoteAddr, closeStream)
		if err != nil {
			serveFallback(w, r)
			return
		}
		defer cleanup()
		defer closeStream()
		if outerUser != "" && !inboundUserAllowed(inboundID, user) {
			return
		}
		_ = controller.SetReadDeadline(time.Time{})

		log.Printf("[XHTTP] Native stream for user '%s' to %s (%s)", user, dest, proto)

		// In-Protocol Speedtest Check
		if isSpeedtestAddr(dest) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)
			flusher.Flush()

			duplex := newServerDuplexConn(r, w, flusher)
			handleSpeedtestStream(duplex, user)
			return
		}

		// UDP over XHTTP stream
		if proto == "udp" {
			udpAddr, err := safeResolveUDP(dest)
			if err != nil {
				log.Printf("[XHTTP-UDP] Resolve failed for %s: %v", dest, err)
				http.Error(w, "UDP resolve failed: "+err.Error(), http.StatusForbidden)
				return
			}
			uConn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				log.Printf("[XHTTP-UDP] Dial failed for %s: %v", dest, err)
				http.Error(w, "UDP dial failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer uConn.Close()
			if !targets.Attach(uConn) {
				return
			}

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)
			flusher.Flush()

			var once sync.Once
			closeBoth := func() {
				_ = uConn.Close()
				_ = r.Body.Close()
			}

			done := make(chan struct{})
			ctx := r.Context()
			go func() {
				select {
				case <-ctx.Done():
					once.Do(closeBoth)
				case <-done:
				}
			}()
			defer func() {
				close(done)
				once.Do(closeBoth)
			}()

			var wg sync.WaitGroup
			wg.Add(2)

			// r.Body -> UDP
			go func() {
				defer wg.Done()
				defer once.Do(closeBoth)
				lenBuf := make([]byte, 2)
				for {
					if _, err := io.ReadFull(r.Body, lenBuf); err != nil {
						return
					}
					pktLen := binary.BigEndian.Uint16(lenBuf)
					if pktLen == 0 || pktLen > 65507 {
						return
					}
					pkt := make([]byte, pktLen)
					if _, err := io.ReadFull(r.Body, pkt); err != nil {
						return
					}
					if !recordUserTraffic(user, uint64(pktLen), 0) {
						return
					}
					if _, err := uConn.Write(pkt); err != nil {
						return
					}
				}
			}()

			// UDP -> w (length-prefixed)
			go func() {
				defer wg.Done()
				defer once.Do(closeBoth)
				buf := make([]byte, 65536)
				for {
					_ = uConn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := uConn.Read(buf[2:])
					if n > 0 {
						response := dnsUDPResponse(dest, buf[2:2+n])
						n = copy(buf[2:], response)
						if !recordUserTraffic(user, 0, uint64(n)) {
							return
						}
						binary.BigEndian.PutUint16(buf[:2], uint16(n))
						if _, wErr := w.Write(buf[:2+n]); wErr != nil {
							return
						}
						flusher.Flush()
					}
					if err != nil {
						return
					}
				}
			}()

			wg.Wait()
			return
		}

		// Standard TCP over XHTTP stream
		targetConn, err := safeDialTCP(dest, 10*time.Second)
		if err != nil {
			log.Printf("[XHTTP] Blocked or failed to dial %s: %v", dest, err)
			http.Error(w, "Dial blocked or failed: "+err.Error(), http.StatusForbidden)
			return
		}
		defer targetConn.Close()
		if !targets.Attach(targetConn) {
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		var once sync.Once
		closeBoth := func() {
			_ = targetConn.Close()
			_ = r.Body.Close()
		}

		done := make(chan struct{})
		ctx := r.Context()
		go func() {
			select {
			case <-ctx.Done():
				once.Do(closeBoth)
			case <-done:
			}
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		// Uplink: r.Body -> targetConn
		go func() {
			defer wg.Done()
			buf := make([]byte, 32768)
			for {
				n, rErr := r.Body.Read(buf)
				if n > 0 {
					if !recordUserTraffic(user, uint64(n), 0) {
						once.Do(closeBoth)
						return
					}
					if _, wErr := targetConn.Write(buf[:n]); wErr != nil {
						once.Do(closeBoth)
						return
					}
				}
				if rErr != nil {
					// Proper TCP Half-Close: client finished sending request.
					// Send TCP FIN to target without closing Downlink!
					if tcpConn, ok := targetConn.(*net.TCPConn); ok {
						_ = tcpConn.CloseWrite()
					} else {
						once.Do(closeBoth)
					}
					return
				}
			}
		}()

		// Downlink: targetConn -> w
		go func() {
			defer wg.Done()
			defer once.Do(closeBoth)
			fw := &flushWriter{w: w, f: flusher}
			buf := make([]byte, 32768)
			for {
				_ = targetConn.SetReadDeadline(time.Now().Add(120 * time.Second))
				n, rErr := targetConn.Read(buf)
				if n > 0 {
					if !recordUserTraffic(user, 0, uint64(n)) {
						return
					}
					if _, wErr := fw.Write(buf[:n]); wErr != nil {
						return
					}
				}
				if rErr != nil {
					return
				}
			}
		}()

		wg.Wait()
		close(done)
		once.Do(closeBoth)
	})

	h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: handler,
	})
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 && fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func writeHTTPRedirect(conn net.Conn, sni string) {
	if sni == "" {
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	location := "https://" + sni + "/"
	body := "<html><head><meta http-equiv=\"refresh\" content=\"0; url=" + location + "\"></head><body>Redirecting...</body></html>"
	resp := "HTTP/1.1 302 Found\r\n" +
		"Connection: close\r\n" +
		"Location: " + location + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body
	_, _ = conn.Write([]byte(resp))
	_ = conn.SetWriteDeadline(time.Time{})
}

var (
	// One-time token tracking to prevent replay attacks
	usedTokens = make(map[string]time.Time)
	tokenMutex sync.RWMutex
)

// targetSNI must come from the listener configuration, never the received Hello.
func proxyDecoyTo(clientConn net.Conn, targetSNI string, initialBuf []byte) {
	proxyDecoyToContext(context.Background(), clientConn, targetSNI, initialBuf)
}

func proxyDecoyToContext(ctx context.Context, clientConn net.Conn, targetSNI string, initialBuf []byte) {
	if targetSNI == "" {
		targetSNI = "www.microsoft.com"
	}

	serverConn, err := safeDialTCPContext(ctx, net.JoinHostPort(targetSNI, "443"), 4*time.Second)
	if err != nil {
		clientConn.Close()
		return
	}
	var once sync.Once
	closeBoth := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	stop := context.AfterFunc(ctx, func() { once.Do(closeBoth) })
	defer stop()

	if tcpConn, ok := serverConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	// Drain buffered ClientHello data
	if bc, ok := clientConn.(*bufferedConn); ok && len(bc.buf) > 0 {
		initialBuf = bc.buf
		bc.buf = nil
	}

	// Relay initial handshake buffer immediately
	if len(initialBuf) > 0 {
		_ = serverConn.SetWriteDeadline(time.Now().Add(4 * time.Second))
		if err := writeFull(serverConn, initialBuf); err != nil {
			serverConn.Close()
			clientConn.Close()
			return
		}
	}

	const idleTimeout = 30 * time.Second

	copyHalf := func(dst, src net.Conn) {
		defer once.Do(closeBoth)
		buf := make([]byte, 32768)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			n, rErr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
				if wErr := writeFull(dst, buf[:n]); wErr != nil {
					return
				}
			}
			if rErr != nil {
				return
			}
		}
	}

	go copyHalf(serverConn, clientConn)
	copyHalf(clientConn, serverConn)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
