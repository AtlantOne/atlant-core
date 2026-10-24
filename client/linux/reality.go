package main

import (
	"atlant.local/protocol/realityauth"
	"atlant.local/protocol/tlsprofiles"
	"atlant.local/protocol/wire"
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
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/cryptobyte"

	u "github.com/refraction-networking/utls"
)

var (
	sessMu              sync.Mutex
	session             *yamux.Session
	sessionDead         bool
	lastConnectTime     time.Time
	sessionDialCooldown wire.DialCooldown
	activeServerMu      sync.RWMutex
	activeServerAddr    string
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

func writeAtlantHeader(conn net.Conn, network, addr string, cfg *Config) error {
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

	minPad := 16
	maxPad := 256
	if cfg != nil {
		if network == "chaffing" {
			minPad = cfg.ChaffingMinBytes
			maxPad = cfg.ChaffingMaxBytes
		} else {
			minPad = cfg.MinPadding
			maxPad = cfg.MaxPadding
		}
		if !cfg.PaddingEnabled && network != "chaffing" {
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

func dialRemote(cfg *Config, network, addr string) (net.Conn, error) {
	// FakeDNS reverse lookup if target is in virtual pool
	if cfg.FakeDNS && GetFakeDNS() != nil {
		host, port, err := net.SplitHostPort(addr)
		if err == nil && GetFakeDNS().IsFakeIP(host) {
			if domain, ok := GetFakeDNS().GetDomain(host); ok {
				addr = net.JoinHostPort(domain, port)
			}
		}
	}

	// Transport dispatch
	tr := strings.ToLower(cfg.Transport)
	if tr == "xhttp" || strings.ToLower(cfg.TCPProto) == "xhttp" {
		return dialXHTTPStream(cfg, network, addr)
	}

	if tr == "quic" || (network == "udp" && strings.ToLower(cfg.UDPProto) == "quic") || (network == "tcp" && strings.ToLower(cfg.TCPProto) == "quic") {
		return dialQUICStream(cfg, network, addr)
	}

	// Reality TCP: Direct 1-to-1 (default) or Yamux Multiplexing
	if cfg.Mux {
		return dialRealityMux(cfg, network, addr)
	}
	return dialRealityDirect(cfg, network, addr)
}

func dialRealityDirect(cfg *Config, network, addr string) (net.Conn, error) {
	conn, err := dialRealityConn(cfg)
	if err != nil {
		return nil, fmt.Errorf("dial reality direct failed: %w", err)
	}
	if errHdr := writeAtlantHeader(conn, network, addr, cfg); errHdr != nil {
		conn.Close()
		return nil, errHdr
	}
	return conn, nil
}

func dialQUICBootstrap(cfg *Config) (net.Conn, error) {
	if cfg.WireVersion != 6 {
		return dialRealityConn(cfg)
	}
	sess, err := getYamuxSession(cfg)
	if err != nil {
		return nil, err
	}
	return sess.Open()
}

func dialRealityMux(cfg *Config, network, addr string) (net.Conn, error) {
	sess, err := getYamuxSession(cfg)
	if err != nil {
		return nil, err
	}
	stream, err := sess.Open()
	if err != nil {
		sessMu.Lock()
		if session == sess {
			sessionDead = true
			session = nil
		}
		sessMu.Unlock()
		return nil, err
	}
	if errHdr := writeAtlantHeader(stream, network, addr, cfg); errHdr != nil {
		stream.Close()
		return nil, errHdr
	}
	return stream, nil
}

func getYamuxSession(cfg *Config) (_ *yamux.Session, err error) {
	sessMu.Lock()
	defer sessMu.Unlock()

	if session != nil && !session.IsClosed() && !sessionDead {
		if time.Since(lastConnectTime) < 12*time.Minute {
			return session, nil
		}
		oldSess := session
		session = nil
		go func() {
			time.Sleep(30 * time.Second)
			_ = oldSess.Close()
		}()
	}

	if err := sessionDialCooldown.RetryError(time.Now()); err != nil {
		return nil, err
	}
	defer func() { sessionDialCooldown.Record(err, time.Now()) }()
	conn, err := dialRealityConn(cfg)
	if err != nil {
		return nil, err
	}

	yConfig := yamux.DefaultConfig()
	yConfig.EnableKeepAlive = true
	yConfig.KeepAliveInterval = 15 * time.Second
	yConfig.ConnectionWriteTimeout = 10 * time.Second
	yConfig.StreamOpenTimeout = 10 * time.Second
	yConfig.LogOutput = io.Discard

	sess, err := yamux.Client(conn, yConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	session = sess
	sessionDead = false
	lastConnectTime = time.Now()
	return session, nil
}

func startChaffingWorker(ctx context.Context, cfg *Config) {
	if !cfg.ChaffingEnabled {
		return
	}
	interval := cfg.ChaffingInterval
	if interval <= 0 {
		interval = 10
	}

	for {
		jitterMs := interval*700 + int(time.Now().UnixNano()%int64(interval*650+1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(jitterMs) * time.Millisecond):
		}

		if !cfg.ChaffingEnabled {
			continue
		}
		go func() {
			conn, err := dialRealityConn(cfg)
			if err != nil {
				return
			}
			defer conn.Close()
			_ = writeAtlantHeader(conn, "chaffing", "127.0.0.1:0", cfg)
		}()
	}
}

func dialServer(addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.Dial("tcp", addr)
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
	fin.AddUint8(0x14)
	fin.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(verifyData)
	})
	finBytes, err := fin.Bytes()
	if err != nil {
		return nil, fmt.Errorf("cryptobyte fin.Bytes error: %w", err)
	}
	innerPlaintext := append(finBytes, 0x16)

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

func buildFallbackClientHello(serverName string, sessionID [32]byte, clientPubKey []byte) []byte {
	clientRandom := make([]byte, 32)
	rand.Read(clientRandom)

	var hello cryptobyte.Builder
	hello.AddUint8(0x01)
	hello.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303)
		b.AddBytes(clientRandom)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionID[:])
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(getRandGREASE())
			b.AddUint16(0x1301)
			b.AddUint16(0x1302)
			b.AddUint16(0x1303)
			b.AddUint16(0xc02b)
			b.AddUint16(0xc02f)
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(0x00)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(getRandGREASE())
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {})

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

			b.AddUint16(0x000a)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(getRandGREASE())
					b.AddUint16(0x001d)
				})
			})

			b.AddUint16(0x002b)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(getRandGREASE())
					b.AddUint16(0x0304)
					b.AddUint16(0x0303)
				})
			})

			b.AddUint16(0x0033)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16(0x001d)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(clientPubKey)
					})
				})
			})

			b.AddUint16(0x0015)
			b.AddUint16LengthPrefixed(func(pad *cryptobyte.Builder) {
				var rnd [1]byte
				_, _ = rand.Read(rnd[:])
				padSize := 150 + int(rnd[0])%70
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

	spec.GetSessionID = func(ticket []byte) [32]byte {
		var token [32]byte
		copy(token[:], sessionID)
		return token
	}

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

func extractHandshakePayload(records []byte) []byte {
	var payload []byte
	offset := 0
	for offset+5 <= len(records) {
		recType := records[offset]
		recLen := int(binary.BigEndian.Uint16(records[offset+3 : offset+5]))
		if offset+5+recLen > len(records) {
			break
		}
		if recType == 0x16 {
			payload = append(payload, records[offset+5:offset+5+recLen]...)
		}
		offset += 5 + recLen
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

func parseServerHello(record []byte) (serverPubKey []byte, handshakeMsg []byte, cipherSuite uint16, err error) {
	if len(record) < 5 || record[0] != 0x16 {
		return nil, nil, 0, fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+recLen {
		return nil, nil, 0, fmt.Errorf("short record")
	}
	handshake := cryptobyte.String(record[5 : 5+recLen])
	var hsType uint8
	var hsData cryptobyte.String
	if !handshake.ReadUint8(&hsType) || hsType != 0x02 || !handshake.ReadUint24LengthPrefixed(&hsData) {
		return nil, nil, 0, fmt.Errorf("not a ServerHello message")
	}
	handshakeMsg = record[5 : 5+recLen]

	var legacyVersion uint16
	var serverRandom []byte
	var sessID cryptobyte.String
	var cs uint16
	var compression uint8
	var exts cryptobyte.String

	if !hsData.ReadUint16(&legacyVersion) ||
		!hsData.ReadBytes(&serverRandom, 32) ||
		!hsData.ReadUint8LengthPrefixed(&sessID) ||
		!hsData.ReadUint16(&cs) ||
		!hsData.ReadUint8(&compression) ||
		!hsData.ReadUint16LengthPrefixed(&exts) {
		return nil, nil, 0, fmt.Errorf("malformed ServerHello")
	}
	cipherSuite = cs

	var helloRetryRequestRandom = []byte{
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
	}
	if bytes.Equal(serverRandom, helloRetryRequestRandom) {
		return nil, nil, 0, fmt.Errorf("server requested HelloRetryRequest (RFC 8446 Section 4.1.3)")
	}

	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
			break
		}
		if extType == 0x0033 {
			var group uint16
			var keyExchange cryptobyte.String
			if extData.ReadUint16(&group) && group == 0x001d && extData.ReadUint16LengthPrefixed(&keyExchange) {
				if len(keyExchange) == 32 {
					serverPubKey = make([]byte, 32)
					copy(serverPubKey, keyExchange)
					return serverPubKey, handshakeMsg, cipherSuite, nil
				}
			}
		}
	}
	return nil, nil, 0, fmt.Errorf("X25519 key_share not found in ServerHello")
}

func dialRealityConn(cfg *Config) (net.Conn, error) {
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
				time.Sleep(delay)
			}

			rawConn, err := dialServer(serverAddr)
			if err != nil {
				lastErr = err
				continue
			}

			if tcpConn, ok := rawConn.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			curve := ecdh.X25519()
			clientEphPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			clientEphPub := clientEphPriv.PublicKey().Bytes()

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

			chRecord, utlsErr := buildClientHelloWithUTLS(cfg.SNI, sessionIDToken[:], clientEphPub, cfg.Fingerprint)
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

			rawConn.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tlsprofiles.WriteClientHello(rawConn, chRecord); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			chMsg := extractHandshakePayload(chRecord)

			shHdr := make([]byte, 5)
			if _, err := io.ReadFull(rawConn, shHdr); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			shLen := int(binary.BigEndian.Uint16(shHdr[3:5]))
			shRecord := make([]byte, 5+shLen)
			copy(shRecord[:5], shHdr)
			if _, err := io.ReadFull(rawConn, shRecord[5:]); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}

			serverPubKey, shMsg, cipherSuite, err := parseServerHello(shRecord)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}

			serverPeerKey, err := curve.NewPublicKey(serverPubKey)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			sharedSecret, err := clientEphPriv.ECDH(serverPeerKey)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}

			var staticShared []byte
			if spkHex := strings.TrimSpace(cfg.ServerPubKey); spkHex != "" {
				if len(spkHex) == 64 {
					if spkBytes, err := hex.DecodeString(spkHex); err == nil {
						if spk, err := curve.NewPublicKey(spkBytes); err == nil {
							if ss, err := clientEphPriv.ECDH(spk); err == nil {
								staticShared = ss
							}
						}
					}
				}
			}

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

			cHsKey, cHsIV, sHsKey, sHsIV, cFinKey, sFinKey, masterSecret := deriveTLS13HandshakeKeys(sharedSecret, staticShared, th1, cipherSuite)

			peekHdr := make([]byte, 5)
			if _, err := io.ReadFull(rawConn, peekHdr); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			var hsRecHdr []byte
			if peekHdr[0] == 0x14 {
				ccsLen := int(binary.BigEndian.Uint16(peekHdr[3:5]))
				if ccsLen > 0 {
					ccsPayload := make([]byte, ccsLen)
					_, _ = io.ReadFull(rawConn, ccsPayload)
				}
				hsRecHdr = make([]byte, 5)
				if _, err := io.ReadFull(rawConn, hsRecHdr); err != nil {
					lastErr = err
					rawConn.Close()
					continue
				}
			} else if peekHdr[0] == 0x17 {
				hsRecHdr = peekHdr
			} else {
				lastErr = fmt.Errorf("unexpected record type: 0x%02x", peekHdr[0])
				rawConn.Close()
				continue
			}

			if hsRecHdr[0] != 0x17 {
				lastErr = fmt.Errorf("unexpected record type: 0x%02x (expected 0x17)", hsRecHdr[0])
				rawConn.Close()
				continue
			}
			hsRecLen := int(binary.BigEndian.Uint16(hsRecHdr[3:5]))
			hsPayload := make([]byte, hsRecLen)
			if _, err := io.ReadFull(rawConn, hsPayload); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}

			sAead, err := createTLS13AEAD(cipherSuite, sHsKey)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			var sIV [12]byte
			copy(sIV[:], sHsIV)
			hsPlaintext, err := sAead.Open(nil, makeTLS13Nonce(sIV, 0), hsPayload, hsRecHdr)
			if err != nil {
				lastErr = fmt.Errorf("handshake AEAD decrypt failed: %w", err)
				rawConn.Close()
				continue
			}

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

			expectedFinMac := hmac.New(hashFunc, sFinKey)
			expectedFinMac.Write(th2)
			expectedFin := expectedFinMac.Sum(nil)

			if !hmac.Equal(finMsg[4:], expectedFin) {
				lastErr = fmt.Errorf("server Finished verification failed")
				rawConn.Close()
				continue
			}

			cFinRecord, err := buildEncryptedClientFinished(cipherSuite, cHsKey, cHsIV, cFinKey, th3)
			if err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}
			if _, err := rawConn.Write(cFinRecord); err != nil {
				lastErr = err
				rawConn.Close()
				continue
			}

			cAppKey, cAppIV, sAppKey, sAppIV := deriveTLS13AppKeys(masterSecret, th3, cipherSuite)

			secureConn, err := newRealityConn(rawConn, cipherSuite, cAppKey, cAppIV, sAppKey, sAppIV, 0, 0)
			if err != nil {
				rawConn.Close()
				return nil, err
			}
			rawConn.SetDeadline(time.Time{})
			setActiveServer(serverAddr)
			return secureConn, nil
		}
	}

	return nil, fmt.Errorf("failed to connect to server: %w", lastErr)
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
				padLen = 16 + int(rnd[0])%112
				if chunkSize+1+padLen > maxPlaintext {
					padLen = 0
				}
			}
		}

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
		cipherSlice := c.decBuf[:recLen]
		if _, err := io.ReadFull(c.Conn, cipherSlice); err != nil {
			return 0, err
		}

		if err := wire.CheckTLSKeyUsage(c.decNonce); err != nil {
			return 0, err
		}
		nonce := wire.TLSNonce(&c.readNonce, c.decIV, c.decNonce)
		c.decNonce++
		plaintext, err := c.decCipher.Open(cipherSlice[:0], nonce, cipherSlice, header[:])
		if err != nil {
			return 0, fmt.Errorf("AEAD decrypt failed: %w", err)
		}

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
				continue
			}
			n := copy(p, plaintext)
			if n < len(plaintext) {
				// Drain the owned decrypt buffer before reading the next record.
				c.readBuf = plaintext[n:]
			}
			return n, nil
		case 0x16: // Post-handshake message (NewSessionTicket, KeyUpdate)
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
