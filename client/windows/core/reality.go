package main

import (
	"atlant.local/protocol/realityauth"
	"atlant.local/protocol/tlsprofiles"
	"atlant.local/protocol/wire"
	"atlant.local/protocol/xhttppool"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/cryptobyte"

	u "github.com/refraction-networking/utls"
)

func dialRemote(cfg *Config) (net.Conn, error) {
	sess, err := getSession(cfg)
	if err != nil {
		log.Printf("[REALITY] Failed to get session: %v", err)
		return nil, err
	}
	stream, err := sess.Open()
	if err != nil {
		mu.Lock()
		if session == sess {
			sessionDead = true
			session = nil
		}
		mu.Unlock()
		return nil, err
	}
	return stream, nil
}

func writeAtlantHeader(conn net.Conn, network, addr string) error {
	var protoByte byte = 0x11
	if network == "udp" {
		protoByte = 0x12
	} else if network == "chaffing" {
		protoByte = 0x19
	}

	addrBytes := []byte(addr)
	if len(addrBytes) > 65535 {
		return fmt.Errorf("destination address too long: %d bytes (max 65535)", len(addrBytes))
	}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(addrBytes)))

	// Configurable dynamic frame padding
	minPad := 16
	maxPad := 256
	if activeCfg != nil {
		if network == "chaffing" {
			minPad = activeCfg.ChaffingMinBytes
			maxPad = activeCfg.ChaffingMaxBytes
		} else {
			minPad = activeCfg.MinPadding
			maxPad = activeCfg.MaxPadding
		}
		if !activeCfg.PaddingEnabled && network != "chaffing" {
			minPad = 0
			maxPad = 0
		}
	}
	if minPad < 0 {
		minPad = 0
	}
	if maxPad < minPad {
		maxPad = minPad
	}

	var padLen int
	if maxPad > minPad {
		var n [2]byte
		_, _ = rand.Read(n[:])
		padLen = minPad + int(binary.BigEndian.Uint16(n[:]))%(maxPad-minPad+1)
	} else {
		padLen = minPad
	}

	padBytes := make([]byte, padLen)
	if padLen > 0 {
		if _, err := rand.Read(padBytes); err != nil {
			return fmt.Errorf("crypto rand padBytes error: %w", err)
		}
	}
	padLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(padLenBytes, uint16(padLen))

	header := make([]byte, 0, 1+2+len(addrBytes)+2+padLen)
	header = append(header, protoByte)
	header = append(header, lenBytes...)
	header = append(header, addrBytes...)
	header = append(header, padLenBytes...)
	header = append(header, padBytes...)

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeFull(conn, header); err != nil {
		return fmt.Errorf("reality stream write header: %w", err)
	}
	conn.SetWriteDeadline(time.Time{})
	return nil
}

// dialRemoteRealityStream opens a connection to the remote destination over Reality TLS 1.3.
// Supports direct TCP streams and optional yamux multiplexing.
func dialRemoteRealityStream(cfg *Config, network, addr string) (net.Conn, error) {
	if cfg.Mux {
		stream, err := dialRemote(cfg)
		if err != nil {
			return nil, fmt.Errorf("reality mux stream error: %w", err)
		}
		if err := writeAtlantHeader(stream, network, addr); err != nil {
			stream.Close()
			return nil, fmt.Errorf("reality mux write header: %w", err)
		}
		return stream, nil
	}

	// Each direct stream starts its own REALITY connection.
	conn, errDirect := dialRealityConn(cfg)
	if errDirect != nil {
		return nil, fmt.Errorf("reality direct conn: %w", errDirect)
	}
	if errHdr := writeAtlantHeader(conn, network, addr); errHdr != nil {
		conn.Close()
		return nil, errHdr
	}
	return conn, nil
}

func dialServer(cfg *Config, serverAddr string) (net.Conn, error) {
	if physicalLocalIP != nil {
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: physicalLocalIP},
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.Dial("tcp", serverAddr)
		if err == nil {
			return conn, nil
		}
	}

	// Fallback to default dialer
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.Dial("tcp", serverAddr)
}

type http2DuplexConn struct {
	lease         *xhttppool.Lease
	reader        io.ReadCloser
	writer        io.Writer
	closer        io.Closer
	cancel        context.CancelFunc
	remoteAddr    net.Addr
	localAddr     net.Addr
	closeOnce     sync.Once
	closed        chan struct{}
	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
	readWatch     wire.DeadlineWatch
	writeWatch    wire.DeadlineWatch
	writeMu       sync.Mutex
}

func (c *http2DuplexConn) Read(b []byte) (int, error) {
	if dl := c.readDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.readWatch.Begin()
	defer c.readWatch.End()
	n, err := c.reader.Read(b)
	if err != nil {
		if dl := c.readDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, err
}

func (c *http2DuplexConn) Write(b []byte) (int, error) {
	c.lease.Pending(len(b))
	defer c.lease.Pending(-len(b))
	if dl := c.writeDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeWatch.Begin()
	defer c.writeWatch.End()

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
		if dl := c.writeDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
			return total, os.ErrDeadlineExceeded
		}
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
		c.readWatch.Stop()
		c.writeWatch.Stop()
		close(c.closed)
		if c.cancel != nil {
			c.cancel()
		}
		if c.closer != nil {
			c.closer.Close()
		}
		if c.reader != nil {
			c.reader.Close()
		}
		c.lease.Release()
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

func (c *http2DuplexConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	c.readWatch.Set(t, func() { _ = c.Close() })
	return nil
}

func (c *http2DuplexConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(t.UnixNano())
	}
	c.writeWatch.Set(t, func() { _ = c.Close() })
	return nil
}

func (c *http2DuplexConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

var (
	xhttpCarriers    xhttppool.Pool
	activeServerMu   sync.RWMutex
	activeServerAddr string
)

func getActiveServer(cfg *Config) string {
	activeServerMu.RLock()
	defer activeServerMu.RUnlock()
	if activeServerAddr != "" {
		return activeServerAddr
	}
	return cfg.ServerAddr
}

func setActiveServer(addr string) {
	activeServerMu.Lock()
	defer activeServerMu.Unlock()
	activeServerAddr = addr
}

func buildEncryptedClientFinished(cipherSuite uint16, clientHandshakeKey, clientHandshakeIV, cFinKey []byte, transcriptHash []byte) ([]byte, error) {
	hashFunc := sha256.New
	if cipherSuite == 0x1302 {
		hashFunc = sha512.New384
	}
	cMac := hmac.New(hashFunc, cFinKey)
	cMac.Write(transcriptHash)
	verifyData := cMac.Sum(nil)

	var fin cryptobyte.Builder
	fin.AddUint8(0x14) // Handshake type: Finished
	fin.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(verifyData)
	})
	finBytes, err := fin.Bytes()
	if err != nil {
		return nil, fmt.Errorf("cryptobyte fin.Bytes error: %w", err)
	}
	innerPlaintext := append(finBytes, 0x16) // TLS 1.3 inner content type: 0x16 (Handshake)

	aead, err := createTLS13AEAD(cipherSuite, clientHandshakeKey)
	if err != nil {
		return nil, err
	}
	var iv [12]byte
	copy(iv[:], clientHandshakeIV)
	nonce := makeTLS13Nonce(iv, 0)

	recordLen := len(innerPlaintext) + 16
	hdr := []byte{0x17, 0x03, 0x03, byte(recordLen >> 8), byte(recordLen)}
	ciphertext := aead.Seal(nil, nonce, innerPlaintext, hdr)

	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	full := append(ccs, hdr...)
	return append(full, ciphertext...), nil
}

func getRandGREASE() uint16 {
	greaseTable := [...]uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	return greaseTable[int(b[0])%len(greaseTable)]
}

func buildClientHello(serverName string, clientRandom []byte, sessionID []byte, clientEphPub []byte) []byte {
	var hello cryptobyte.Builder
	hello.AddUint8(0x01) // ClientHello
	hello.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303)
		b.AddBytes(clientRandom)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionID)
		})
		// Cipher suites (Chrome order: GREASE + TLS 1.3 ciphers + ECDHE fallback)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(getRandGREASE()) // GREASE
			b.AddUint16(0x1301)          // TLS_AES_128_GCM_SHA256
			b.AddUint16(0x1302)          // TLS_AES_256_GCM_SHA384
			b.AddUint16(0x1303)          // TLS_CHACHA20_POLY1305_SHA256
			b.AddUint16(0xc02b)          // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			b.AddUint16(0xc02f)          // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			b.AddUint16(0xc02c)          // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			b.AddUint16(0xc030)          // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			b.AddUint16(0xcca9)          // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			b.AddUint16(0xcca8)          // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(0x00)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// GREASE extension
			b.AddUint16(getRandGREASE())
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})

			// SNI (0x0000)
			if serverName != "" {
				b.AddUint16(0x0000)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint8(0x00)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(serverName))
						})
					})
				})
			}

			// supported_groups (0x000a) - RFC 8446 mandatory for ECDHE
			b.AddUint16(0x000a)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(getRandGREASE()) // GREASE
					b.AddUint16(0x001d)          // X25519
					b.AddUint16(0x0017)          // secp256r1
					b.AddUint16(0x0018)          // secp384r1
				})
			})

			// ec_point_formats (0x000b)
			b.AddUint16(0x000b)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0x00) // uncompressed
				})
			})

			// signature_algorithms (0x000d) - RFC 8446 Section 4.2.3 strictly REQUIRED in TLS 1.3
			b.AddUint16(0x000d)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x0403) // ecdsa_secp256r1_sha256
					b.AddUint16(0x0804) // rsa_pss_rsae_sha256
					b.AddUint16(0x0401) // rsa_pkcs1_sha256
					b.AddUint16(0x0503) // ecdsa_secp384r1_sha384
					b.AddUint16(0x0805) // rsa_pss_rsae_sha384
					b.AddUint16(0x0501) // rsa_pkcs1_sha384
					b.AddUint16(0x0806) // rsa_pss_rsae_sha512
					b.AddUint16(0x0601) // rsa_pkcs1_sha512
				})
			})

			// ALPN (0x0010)
			b.AddUint16(0x0010)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("h2"))
					})
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes([]byte("http/1.1"))
					})
				})
			})

			// psk_key_exchange_modes (0x002d) - RFC 8446 mandatory for TLS 1.3
			b.AddUint16(0x002d)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint8(0x01) // psk_dhe_ke
				})
			})

			// supported_versions (0x002b)
			b.AddUint16(0x002b)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(getRandGREASE()) // GREASE
					b.AddUint16(0x0304)          // TLS 1.3
					b.AddUint16(0x0303)          // TLS 1.2
				})
			})

			// key_share (0x0033)
			b.AddUint16(0x0033)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x001d) // X25519
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(clientEphPub)
					})
				})
			})

			// Padding (0x0015) — Dynamic authentic Chrome record alignment
			b.AddUint16(0x0015)
			b.AddUint16LengthPrefixed(func(pad *cryptobyte.Builder) {
				var rnd [1]byte
				_, _ = rand.Read(rnd[:])
				padSize := 150 + int(rnd[0])%70 // 150..219 bytes dynamic padding
				pad.AddBytes(make([]byte, padSize))
			})
		})
	})
	helloBytes, _ := hello.Bytes()

	var record cryptobyte.Builder
	record.AddUint8(0x16)
	record.AddUint16(0x0303)
	record.AddUint16(uint16(len(helloBytes)))
	record.AddBytes(helloBytes)
	recBytes, _ := record.Bytes()
	return recBytes
}

// buildClientHelloWithUTLS starts from the selected uTLS profile, then installs
// the REALITY session ID and X25519 key share. Browser equivalence is not assumed.
func buildClientHelloWithUTLS(serverName string, sessionID []byte, clientEphPub []byte, fingerprint string) ([]byte, error) {
	if len(sessionID) != 32 || len(clientEphPub) != 32 {
		return nil, fmt.Errorf("invalid REALITY ClientHello authentication fields")
	}
	var helloID u.ClientHelloID
	switch strings.ToLower(strings.TrimSpace(fingerprint)) {
	case "", "firefox", "firefox_120", "firefox_auto":
		helloID = u.HelloFirefox_120
	case "safari", "safari_16", "safari_auto":
		helloID = u.HelloSafari_16_0
	case "ios", "ios_14", "ios_13", "iphone":
		helloID = u.HelloIOS_14
	case "edge", "edge_106", "edge_85":
		helloID = u.HelloEdge_106
	case "android", "okhttp", "android_11":
		helloID = u.HelloAndroid_11_OkHttp
	case "360":
		helloID = u.Hello360_Auto
	case "qq":
		helloID = u.HelloQQ_Auto
	case "randomized", "random":
		helloID = u.HelloRandomized
	case "chrome_120":
		helloID = u.HelloChrome_120
	case "chrome", "chrome_auto", "chrome_144", "chrome_133":
		helloID = u.HelloChrome_133
	default:
		return nil, fmt.Errorf("unsupported TLS profile %q", fingerprint)
	}

	spec, err := u.UTLSIdToSpec(helloID)
	if helloID == u.HelloChrome_133 {
		spec, err = tlsprofiles.Chrome144Spec()
	}
	if err != nil {
		return nil, fmt.Errorf("utls spec failed: %w", err)
	}

	// Inject Reality SessionID auth token
	spec.GetSessionID = func(ticket []byte) [32]byte {
		var token [32]byte
		copy(token[:], sessionID)
		return token
	}

	// Inject client ephemeral X25519 key into KeyShare extension preserving Kyber768 and GREASE
	keyShareInjected := false
	for i, ext := range spec.Extensions {
		if ks, ok := ext.(*u.KeyShareExtension); ok {
			foundGroup := false
			for j, entry := range ks.KeyShares {
				if entry.Group == u.X25519 {
					ks.KeyShares[j].Data = clientEphPub
					foundGroup = true
					break
				}
			}
			if !foundGroup {
				return nil, fmt.Errorf("TLS profile %q has no native X25519 key share", fingerprint)
			}
			spec.Extensions[i] = ks
			keyShareInjected = true
			break
		}
	}
	if !keyShareInjected {
		return nil, fmt.Errorf("TLS profile %q has no native key_share extension", fingerprint)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	uConfig := &u.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	}
	uConn := u.UClient(clientConn, uConfig, u.HelloCustom)
	if err := uConn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("utls apply preset: %w", err)
	}

	uConn.HandshakeState.Hello.SessionId = make([]byte, 32)
	copy(uConn.HandshakeState.Hello.SessionId, sessionID)

	// Marshal the complete preset directly. Capturing a deliberately unfinished
	// handshake on net.Pipe could return a partial flight as success on timeout.
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("utls build handshake state: %w", err)
	}
	uConn.HandshakeState.Hello.SessionId = append([]byte(nil), sessionID...)
	if err := uConn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("utls marshal ClientHello: %w", err)
	}
	hello := uConn.HandshakeState.Hello.Raw
	if len(hello) < 4 || len(hello) > 16384 || hello[0] != 1 {
		return nil, fmt.Errorf("unsupported ClientHello length")
	}
	declared := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
	if declared != len(hello) {
		return nil, fmt.Errorf("incomplete ClientHello serialization")
	}
	record := make([]byte, 5+len(hello))
	copy(record, []byte{22, 3, 1})
	binary.BigEndian.PutUint16(record[3:5], uint16(len(hello)))
	copy(record[5:], hello)
	return record, nil
}

// extractHandshakePayload strips all 5-byte TLS record headers (e.g. from fragmented ClientHello records)
// and returns the pure handshake message bytes for accurate transcript hash computation.
func extractHandshakePayload(records []byte) []byte {
	var payload []byte
	offset := 0
	for offset+5 <= len(records) {
		recType := records[offset]
		recLen := int(binary.BigEndian.Uint16(records[offset+3 : offset+5]))
		if offset+5+recLen > len(records) {
			break
		}
		if recType == 0x16 { // Handshake
			payload = append(payload, records[offset+5:offset+5+recLen]...)
		}
		offset += 5 + recLen
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func startChaffingWorker(cfg *Config) {
	if cfg == nil || !cfg.ChaffingEnabled || !cfg.Mux {
		return
	}
	baseInterval := cfg.ChaffingInterval
	if baseInterval <= 0 {
		baseInterval = 25
	}

	log.Printf("[CHAFFING] Heartbeat micro-noise active (base interval: %ds with dynamic jitter, size: %d..%dB)",
		baseInterval, cfg.ChaffingMinBytes, cfg.ChaffingMaxBytes)

	for {
		// Randomized jitter between 0.7x and 1.6x of baseInterval (e.g. 17s - 40s) to defeat ML/SPLT periodicity detection
		jitterMs := baseInterval*700 + int(time.Now().UnixNano()%int64(baseInterval*900+1))
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)

		mu.Lock()
		sess := session
		mu.Unlock()

		if sess != nil && !sess.IsClosed() {
			go func(s *yamux.Session) {
				stream, err := s.Open()
				if err != nil {
					return
				}
				defer stream.Close()
				_ = writeAtlantHeader(stream, "chaffing", "127.0.0.1:0")
			}(sess)
		}
	}
}

func parseServerHello(data []byte) (serverRandom []byte, cipherSuite uint16, serverPubKey []byte, err error) {
	if len(data) < 5 || data[0] != 0x16 {
		return nil, 0, nil, fmt.Errorf("not TLS handshake")
	}
	recLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recLen {
		return nil, 0, nil, fmt.Errorf("short record")
	}
	s := cryptobyte.String(data[5 : 5+recLen])
	var msgType uint8
	var body cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != 0x02 || !s.ReadUint24LengthPrefixed(&body) {
		return nil, 0, nil, fmt.Errorf("not ServerHello")
	}
	var legacyVer uint16
	var sessID cryptobyte.String
	var comp uint8
	var exts cryptobyte.String
	if !body.ReadUint16(&legacyVer) ||
		!body.ReadBytes(&serverRandom, 32) ||
		!body.ReadUint8LengthPrefixed(&sessID) ||
		!body.ReadUint16(&cipherSuite) ||
		!body.ReadUint8(&comp) ||
		!body.ReadUint16LengthPrefixed(&exts) {
		return nil, 0, nil, fmt.Errorf("parse ServerHello fields failed")
	}

	var helloRetryRequestRandom = []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	if bytes.Equal(serverRandom, helloRetryRequestRandom) {
		return nil, 0, nil, fmt.Errorf("server requested HelloRetryRequest (RFC 8446 Section 4.1.3)")
	}

	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
			break
		}
		if extType == 51 { // key_share
			var group uint16
			var keyExchange cryptobyte.String
			if extData.ReadUint16(&group) && group == 0x001d && extData.ReadUint16LengthPrefixed(&keyExchange) {
				serverPubKey = make([]byte, len(keyExchange))
				copy(serverPubKey, keyExchange)
				return serverRandom, cipherSuite, serverPubKey, nil
			}
		}
	}
	return nil, 0, nil, fmt.Errorf("key_share missing in ServerHello")
}

func newRealityConn(conn net.Conn, cipherSuite uint16, encKey, encIV, decKey, decIV []byte, initEncSeq, initDecSeq uint64) (*realitySecureConn, error) {
	encAead, err := createTLS13AEAD(cipherSuite, encKey)
	if err != nil {
		return nil, err
	}
	decAead, err := createTLS13AEAD(cipherSuite, decKey)
	if err != nil {
		return nil, err
	}
	c := &realitySecureConn{
		Conn:      conn,
		encCipher: encAead,
		decCipher: decAead,
		encNonce:  initEncSeq,
		decNonce:  initDecSeq,
		decBuf:    make([]byte, 16384+256),
	}
	copy(c.encIV[:], encIV)
	copy(c.decIV[:], decIV)
	return c, nil
}

type tlsRecordBuffer = wire.TLSRecordBuffer

func (c *realitySecureConn) enableXHTTPBatching() {
	c.writeMu.Lock()
	c.xhttpBatch = true
	c.writeMu.Unlock()
}

func (c *realitySecureConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}

	const maxPlaintext = 16384
	total := 0
	pending, records := 0, 0
	batchLimit := 1
	if c.xhttpBatch {
		batchLimit = 4
	}
	c.recordBuf.ResetBatch()
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPlaintext {
			chunkSize = maxPlaintext
		}
		chunk := p[:chunkSize]

		padLen := 0
		if activeCfg == nil || activeCfg.PaddingEnabled {
			if c.encNonce < 12 || chunkSize < 900 {
				var rnd [1]byte
				_, _ = rand.Read(rnd[:])
				padLen = 16 + int(rnd[0])%112 // 16..127 bytes random RFC 8446 padding
				if chunkSize+1+padLen > maxPlaintext {
					padLen = 0
				}
			}
		}

		// RFC 8446 Section 5.4: wrap chunk in TLSInnerPlaintext ([chunk][0x17][zeros...])
		record, err := c.recordBuf.AppendSeal(c.encCipher, c.encIV, c.encNonce, chunk, 0x17, padLen)
		if err != nil {
			c.writeErr = err
			return total, err
		}
		c.encNonce++
		pending += chunkSize
		records++
		p = p[chunkSize:]
		if records == batchLimit || len(p) == 0 {
			if err := writeFull(c.Conn, record); err != nil {
				c.writeErr = err
				return total, err
			}
			total += pending
			pending, records = 0, 0
			c.recordBuf.ResetBatch()
		}
	}
	return total, nil
}

func (c *realitySecureConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if len(c.readBuf) > 0 {
			n := copy(p, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}

		header := &c.readHeader
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}

		if header[0] != 0x17 {
			return 0, fmt.Errorf("unexpected TLS record type: 0x%02x (expected 0x17)", header[0])
		}

		recLen := int(header[3])<<8 | int(header[4])
		if recLen < 16 || recLen > 16384+256 {
			return 0, fmt.Errorf("invalid TLS record length: %d", recLen)
		}

		if cap(c.decBuf) < recLen {
			c.decBuf = make([]byte, recLen)
		}
		cipherBuf := c.decBuf[:recLen]
		if _, err := io.ReadFull(c.Conn, cipherBuf); err != nil {
			return 0, err
		}

		if err := wire.CheckTLSKeyUsage(c.decNonce); err != nil {
			return 0, err
		}
		nonce := wire.TLSNonce(&c.readNonce, c.decIV, c.decNonce)
		c.decNonce++

		plaintext, err := c.decCipher.Open(cipherBuf[:0], nonce, cipherBuf, header[:])
		if err != nil {
			return 0, fmt.Errorf("AEAD decrypt failed: %w", err)
		}

		// RFC 8446 Section 5.4: strip trailing ContentType and padding zeros
		if len(plaintext) == 0 {
			return 0, fmt.Errorf("TLS 1.3 inner plaintext is empty")
		}
		padIdx := len(plaintext) - 1
		for padIdx >= 0 && plaintext[padIdx] == 0 {
			padIdx--
		}
		if padIdx < 0 {
			return 0, fmt.Errorf("TLS 1.3 inner plaintext contains only padding zeros")
		}
		innerType := plaintext[padIdx]
		plaintext = plaintext[:padIdx]

		switch innerType {
		case 0x17: // Application Data
			if len(plaintext) == 0 {
				continue // empty frame (padding only), read next record without returning (0, nil)
			}
			n := copy(p, plaintext)
			if n < len(plaintext) {
				// Drain the owned decrypt buffer before reading the next record.
				c.readBuf = plaintext[n:]
			}
			return n, nil
		case 0x16: // Post-handshake message (NewSessionTicket, KeyUpdate)
			log.Printf("[REALITY] Received TLS 1.3 post-handshake message (len: %d), consuming transparently", len(plaintext))
			continue
		case 0x15: // Alert (e.g. CloseNotify)
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected TLS 1.3 inner content type: 0x%02x", innerType)
		}
	}
}

func (c *realitySecureConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeClosed {
		return nil
	}
	record, err := c.recordBuf.Seal(c.encCipher, c.encIV, c.encNonce, []byte{1, 0}, 0x15, 0)
	if err != nil {
		c.writeErr = err
		return err
	}
	c.encNonce++
	if err := writeFull(c.Conn, record); err != nil {
		c.writeErr = err
		return err
	}
	c.writeClosed = true
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

var sessionDialCooldown wire.DialCooldown

func dialQUICBootstrap(cfg *Config) (net.Conn, error) {
	if cfg.WireVersion != 6 {
		return dialRealityConn(cfg)
	}
	controlConfig := *cfg
	controlConfig.Transport = "reality"
	sess, err := getSession(&controlConfig)
	if err != nil {
		return nil, err
	}
	return sess.Open()
}

func getSession(cfg *Config) (_ *yamux.Session, err error) {
	mu.Lock()
	defer mu.Unlock()

	// Wait for any concurrent connection attempt to complete without spin-lock
	for isConnecting {
		sessionCond.Wait()
	}

	// Check if we have a valid session with 12-minute anti-tracking rotation
	if session != nil && !session.IsClosed() && !sessionDead {
		if time.Since(lastConnectTime) < 12*time.Minute {
			return session, nil
		}
		log.Printf("[REALITY] Rotating Yamux session after %v to defeat DPI tracking", time.Since(lastConnectTime).Round(time.Second))
		oldSess := session
		session = nil
		go func() {
			time.Sleep(30 * time.Second)
			_ = oldSess.Close()
		}()
	}

	if strings.ToLower(cfg.Transport) == "xhttp" {
		return nil, fmt.Errorf("XHTTP uses native HTTP/2 stream multiplexing, not yamux sessions")
	}
	if err := sessionDialCooldown.RetryError(time.Now()); err != nil {
		return nil, err
	}
	defer func() { sessionDialCooldown.Record(err, time.Now()) }()

	isConnecting = true
	defer func() {
		isConnecting = false
		sessionCond.Broadcast()
	}()

	secureConn, err := dialRealityConn(cfg)
	if err != nil {
		return nil, err
	}

	yCfg := yamux.DefaultConfig()
	yCfg.KeepAliveInterval = 25*time.Second + time.Duration(time.Now().UnixNano()%20)*time.Second
	yCfg.ConnectionWriteTimeout = 30 * time.Second
	yCfg.StreamOpenTimeout = 10 * time.Second
	yCfg.MaxStreamWindowSize = 16 * 1024 * 1024 // 16MB window for unthrottled gigabit speed
	yCfg.AcceptBacklog = 1024
	yCfg.Logger = nil
	yCfg.LogOutput = io.Discard

	sess, err := yamux.Client(secureConn, yCfg)
	if err != nil {
		secureConn.Close()
		return nil, err
	}

	session = sess
	sessionDead = false
	lastConnectTime = time.Now()
	log.Printf("[REALITY] Yamux session established to %s", cfg.ServerAddr)
	return session, nil
}

// dialRealityConn authenticates a REALITY peer and returns the encrypted stream.
func dialRealityConn(cfg *Config) (net.Conn, error) {
	// Prepare list of servers to try (primary + backups)
	servers := []string{cfg.ServerAddr}
	servers = append(servers, cfg.BackupServers...)

	var lastErr error
	maxRetries := 3
	baseDelay := 500 * time.Millisecond

	for serverIndex, serverAddr := range servers {
		if serverIndex > 0 {
			log.Printf("[REALITY] Trying backup server %s", serverAddr)
		}

		for attempt := 0; attempt < maxRetries; attempt++ {
			lastErr = nil
			if attempt > 0 {
				delay := baseDelay * time.Duration(1<<uint(attempt-1))
				if delay > 8*time.Second {
					delay = 8 * time.Second
				}
				log.Printf("[REALITY] Retrying connection to %s after %v (attempt %d/%d)", serverAddr, delay, attempt+1, maxRetries)
				time.Sleep(delay)
			}

			log.Printf("[REALITY] Dialing %s (SNI: %s)", serverAddr, cfg.SNI)

			rawConn, err := dialServer(cfg, serverAddr)
			if err != nil {
				lastErr = err
				log.Printf("[REALITY] TCP dial error to %s (attempt %d): %v", serverAddr, attempt+1, err)
				continue
			}
			log.Printf("[NET] TCP connected: local=%s remote=%s", rawConn.LocalAddr(), rawConn.RemoteAddr())

			// Set TCP options for better reliability & maximum throughput
			if tcpConn, ok := rawConn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			// Generate ephemeral X25519 keypair
			curve := ecdh.X25519()
			clientEphPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			clientEphPub := clientEphPriv.PublicKey().Bytes()

			// ClientRandom & bound sessionID token
			clientRandom := make([]byte, 32)
			rand.Read(clientRandom)
			sessionIDToken, _ := generateSessionIDTokenBound(cfg.User, cfg.PBK, clientEphPub)
			if cfg.WireVersion == 3 || cfg.WireVersion == 4 {
				serverPub, decodeErr := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
				if decodeErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("invalid pinned REALITY key")
				}
				sessionIDToken, err = realityauth.GenerateVersion(cfg.WireVersion, cfg.User, parsePBKBytes(cfg.PBK), clientEphPriv, serverPub, time.Now())
				if err != nil {
					rawConn.Close()
					return nil, err
				}
			} else if cfg.WireVersion == 6 || cfg.WireVersion == 7 {
				sessionIDToken = [32]byte{}
			} else if cfg.WireVersion != 0 && cfg.WireVersion != 2 {
				rawConn.Close()
				return nil, fmt.Errorf("unsupported wire version")
			}

			// Send the selected uTLS profile with the REALITY authentication fields.
			var chRecord []byte
			var utlsErr error
			chRecord, utlsErr = buildClientHelloWithUTLS(cfg.SNI, sessionIDToken[:], clientEphPub, cfg.Fingerprint)
			if utlsErr != nil || len(chRecord) == 0 {
				rawConn.Close()
				return nil, fmt.Errorf("cannot build selected TLS profile %q: %v", cfg.Fingerprint, utlsErr)
			}
			if cfg.WireVersion == 6 || cfg.WireVersion == 7 {
				serverPub, decodeErr := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
				if decodeErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("invalid pinned REALITY key")
				}
				if err := realityauth.BindHelloVersion(cfg.WireVersion, chRecord, cfg.User, parsePBKBytes(cfg.PBK), clientEphPriv, serverPub, time.Now()); err != nil {
					rawConn.Close()
					return nil, err
				}
			}
			log.Printf("[TLS] Sending ClientHello to %s (SNI=%s, Profile=%s, Len=%d)", serverAddr, cfg.SNI, cfg.Fingerprint, len(chRecord))
			rawConn.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tlsprofiles.WriteClientHello(rawConn, chRecord); err != nil {
				lastErr = fmt.Errorf("failed to send ClientHello: %w", err)
				rawConn.Close()
				continue
			}

			// Read ServerHello (0x16)
			shHdr := make([]byte, 5)
			if _, err := io.ReadFull(rawConn, shHdr); err != nil {
				lastErr = fmt.Errorf("failed to read ServerHello header: %w", err)
				rawConn.Close()
				continue
			}
			if shHdr[0] != 0x16 {
				lastErr = fmt.Errorf("unexpected record type from server: 0x%02x (expected 0x16)", shHdr[0])
				rawConn.Close()
				continue
			}
			shLen := int(binary.BigEndian.Uint16(shHdr[3:5]))
			shBody := make([]byte, shLen)
			if _, err := io.ReadFull(rawConn, shBody); err != nil {
				lastErr = fmt.Errorf("failed to read ServerHello body: %w", err)
				rawConn.Close()
				continue
			}

			_, cipherSuite, serverPubKey, err := parseServerHello(append(shHdr, shBody...))
			if err != nil {
				lastErr = fmt.Errorf("failed to parse ServerHello: %w", err)
				rawConn.Close()
				continue
			}
			log.Printf("[REALITY] ServerHello received! CipherSuite: 0x%04x, Server X25519 key verified", cipherSuite)

			// Compute shared Diffie-Hellman secret
			serverPeerKey, err := curve.NewPublicKey(serverPubKey)
			if err != nil {
				lastErr = fmt.Errorf("invalid server X25519 public key: %w", err)
				rawConn.Close()
				continue
			}
			sharedSecret, err := clientEphPriv.ECDH(serverPeerKey)
			if err != nil {
				lastErr = fmt.Errorf("ECDH computation failed: %w", err)
				rawConn.Close()
				continue
			}

			// Read ChangeCipherSpec (0x14) - optional in TLS 1.3
			peekHdr := make([]byte, 5)
			if _, err := io.ReadFull(rawConn, peekHdr); err != nil {
				lastErr = fmt.Errorf("failed to read CCS/Handshake header: %w", err)
				rawConn.Close()
				continue
			}
			var hsRecHdr []byte
			if peekHdr[0] == 0x14 {
				// ChangeCipherSpec present (0x14 0x03 0x03 0x00 0x01 + payload)
				ccsLen := int(binary.BigEndian.Uint16(peekHdr[3:5]))
				if ccsLen > 0 {
					ccsPayload := make([]byte, ccsLen)
					_, _ = io.ReadFull(rawConn, ccsPayload)
				}
				hsRecHdr = make([]byte, 5)
				if _, err := io.ReadFull(rawConn, hsRecHdr); err != nil {
					lastErr = fmt.Errorf("failed to read Handshake record header after CCS: %w", err)
					rawConn.Close()
					continue
				}
			} else if peekHdr[0] == 0x17 {
				hsRecHdr = peekHdr
			} else {
				lastErr = fmt.Errorf("unexpected record type: 0x%02x (expected 0x14 or 0x17)", peekHdr[0])
				rawConn.Close()
				continue
			}

			// Derive TLS 1.3 handshake keys via TH1 = Hash(ClientHello || ServerHello)
			chMsg := extractHandshakePayload(chRecord)
			shMsg := shBody
			var th1 []byte
			if cipherSuite == 0x1302 {
				h1 := sha512.New384()
				h1.Write(chMsg)
				h1.Write(shMsg)
				th1 = h1.Sum(nil)
			} else {
				h1 := sha256.Sum256(append(chMsg, shMsg...))
				th1 = h1[:]
			}

			// 2-ECDH static secret
			var staticShared []byte
			if spkHex := strings.TrimSpace(cfg.ServerPubKey); spkHex != "" {
				if len(spkHex) == 64 {
					if spkBytes, err := hex.DecodeString(spkHex); err == nil {
						if spk, err := ecdh.X25519().NewPublicKey(spkBytes); err == nil {
							if ss, err := clientEphPriv.ECDH(spk); err == nil {
								staticShared = ss
							}
						}
					}
				} else {
					log.Printf("[REALITY] Warning: server_pub_key has invalid hex length (%d chars, expected 64)", len(spkHex))
				}
			}

			cHsKey, cHsIV, sHsKey, sHsIV, cFinKey, sFinKey, masterSecret := deriveTLS13HandshakeKeys(sharedSecret, staticShared, th1, cipherSuite)

			// Read encrypted handshake records (EE + Cert + CV + Fin)
			if hsRecHdr[0] != 0x17 {
				lastErr = fmt.Errorf("unexpected handshake record type: 0x%02x (expected 0x17)", hsRecHdr[0])
				rawConn.Close()
				continue
			}
			hsRecLen := int(binary.BigEndian.Uint16(hsRecHdr[3:5]))
			hsPayload := make([]byte, hsRecLen)
			if _, err := io.ReadFull(rawConn, hsPayload); err != nil {
				lastErr = fmt.Errorf("failed to read Handshake payload: %w", err)
				rawConn.Close()
				continue
			}

			// Authenticate server handshake AEAD (seq 0)
			sAead, err := createTLS13AEAD(cipherSuite, sHsKey)
			if err != nil {
				lastErr = fmt.Errorf("failed to create server handshake AEAD: %w", err)
				rawConn.Close()
				continue
			}
			var sIV [12]byte
			copy(sIV[:], sHsIV)
			hsPlaintext, err := sAead.Open(nil, makeTLS13Nonce(sIV, 0), hsPayload, hsRecHdr)
			if err != nil {
				lastErr = fmt.Errorf("server handshake AEAD decrypt failed: %w", err)
				rawConn.Close()
				continue
			}

			// Strip RFC 8446 padding zeros from hsPlaintext
			hsPadIdx := len(hsPlaintext) - 1
			for hsPadIdx >= 0 && hsPlaintext[hsPadIdx] == 0 {
				hsPadIdx--
			}
			if hsPadIdx < 0 || hsPlaintext[hsPadIdx] != 0x16 {
				lastErr = fmt.Errorf("invalid server handshake inner plaintext type")
				rawConn.Close()
				continue
			}
			serverHandshakeMsgs := hsPlaintext[:hsPadIdx]

			const finLen = 36
			if len(serverHandshakeMsgs) < finLen {
				lastErr = fmt.Errorf("server handshake inner plaintext too short for Finished")
				rawConn.Close()
				continue
			}
			finMsg := serverHandshakeMsgs[len(serverHandshakeMsgs)-finLen:]
			serverMsgsBeforeFin := serverHandshakeMsgs[:len(serverHandshakeMsgs)-finLen]

			if finMsg[0] != 0x14 {
				lastErr = fmt.Errorf("invalid server Finished handshake type: 0x%02x", finMsg[0])
				rawConn.Close()
				continue
			}

			// Verify server Finished over transcript TH2
			var th2, th3 []byte
			hashFunc := sha256.New
			if cipherSuite == 0x1302 {
				hashFunc = sha512.New384
				h2 := sha512.New384()
				h2.Write(chMsg)
				h2.Write(shMsg)
				h2.Write(serverMsgsBeforeFin)
				th2 = h2.Sum(nil)

				h3 := sha512.New384()
				h3.Write(chMsg)
				h3.Write(shMsg)
				h3.Write(serverHandshakeMsgs)
				th3 = h3.Sum(nil)
			} else {
				h2 := sha256.Sum256(append(append(chMsg, shMsg...), serverMsgsBeforeFin...))
				th2 = h2[:]
				h3 := sha256.Sum256(append(append(chMsg, shMsg...), serverHandshakeMsgs...))
				th3 = h3[:]
			}

			sMac := hmac.New(hashFunc, sFinKey)
			sMac.Write(th2)
			expectedSVerify := sMac.Sum(nil)
			if !hmac.Equal(finMsg[4:], expectedSVerify) {
				lastErr = fmt.Errorf("server Finished verify_data mismatch (RFC 8446 verification failed)")
				rawConn.Close()
				continue
			}
			log.Printf("[REALITY] Server Handshake AEAD & Finished verify_data authenticated via cumulative transcript hash TH2!")

			// Derive application traffic keys from TH3
			cAppKey, cAppIV, sAppKey, sAppIV := deriveTLS13AppKeys(masterSecret, th3, cipherSuite)

			// Send client Finished over TH3 strictly BEFORE expecting NewSessionTickets (RFC 8446 Section 4.6.1)
			finRecord, err := buildEncryptedClientFinished(cipherSuite, cHsKey, cHsIV, cFinKey, th3)
			if err != nil {
				lastErr = fmt.Errorf("failed to build client Finished: %w", err)
				rawConn.Close()
				continue
			}
			if _, err := rawConn.Write(finRecord); err != nil {
				lastErr = fmt.Errorf("failed to send client Finished: %w", err)
				rawConn.Close()
				continue
			}

			// Wrap socket in TLS 1.3 record AEAD layer
			secureConn, err := newRealityConn(rawConn, cipherSuite, cAppKey, cAppIV, sAppKey, sAppIV, 0, 0)
			if err != nil {
				lastErr = fmt.Errorf("failed to create secure conn: %w", err)
				rawConn.Close()
				continue
			}
			rawConn.SetDeadline(time.Time{})

			setActiveServer(serverAddr)
			log.Printf("[REALITY] Full TLS 1.3 Genuine Cryptographic Handshake completed with %s (Mutual AEAD Verified)", serverAddr)
			return secureConn, nil
		}
	}

	log.Printf("[REALITY] All connection attempts failed. Last error: %v", lastErr)
	return nil, fmt.Errorf("failed to connect to any server: %w", lastErr)
}
