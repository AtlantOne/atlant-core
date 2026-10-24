package main

import (
	"atlant.local/protocol/wire"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/hashicorp/yamux"
)

// buildEncryptedServerHandshake encodes the REALITY handshake in TLS 1.3 records.
// CertificateVerify is synthetic, not a donor signature; authentication uses
// the REALITY key schedule and Finished. The returned hash includes ServerFinished.
func buildEncryptedServerHandshake(
	sni string,
	cipherSuite uint16,
	serverHandshakeKey, serverHandshakeIV []byte,
	sFinKey []byte,
	clientHelloHandshake, serverHelloHandshake []byte,
	selectedALPN string,
) ([]byte, [32]byte, error) {
	// EncryptedExtensions (0x08)
	var ee cryptobyte.Builder
	ee.AddUint8(0x08)
	ee.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(exts *cryptobyte.Builder) {
			if selectedALPN != "" {
				exts.AddUint16(0x0010) // ALPN (RFC 8446 Section 4.2: only if client offered ALPN)
				exts.AddUint16LengthPrefixed(func(alpn *cryptobyte.Builder) {
					alpn.AddUint16LengthPrefixed(func(protoList *cryptobyte.Builder) {
						protoList.AddUint8LengthPrefixed(func(p *cryptobyte.Builder) {
							p.AddBytes([]byte(selectedALPN))
						})
					})
				})
			}
		})
	})
	eeBytes, _ := ee.Bytes()

	// Certificate (0x0b) - TLS 1.3 certificate message with donor ASN.1 DER certificate
	ders := getDonorCertificateChain(sni)
	var cert cryptobyte.Builder
	cert.AddUint8(0x0b)
	cert.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x00) // certificate_request_context (empty)
		b.AddUint24LengthPrefixed(func(certList *cryptobyte.Builder) {
			for _, der := range ders {
				certList.AddUint24LengthPrefixed(func(entry *cryptobyte.Builder) {
					entry.AddBytes(der)
				})
				certList.AddUint16(0x0000) // empty extensions
			}
		})
	})
	certBytes, _ := cert.Bytes()

	// CertificateVerify (0x0f)
	// Match signature algorithm to the donor certificate's public key algorithm (RFC 8446 Table 4)
	sigScheme := uint16(0x0804) // rsa_pss_rsae_sha256 default
	var cvSig []byte
	if len(ders) > 0 {
		if parsedCert, err := x509.ParseCertificate(ders[0]); err == nil {
			switch parsedCert.PublicKeyAlgorithm {
			case x509.ECDSA:
				sigScheme = 0x0403 // default ecdsa_secp256r1_sha256
				coordLen := 32
				if ecdsaPub, ok := parsedCert.PublicKey.(*ecdsa.PublicKey); ok && ecdsaPub != nil && ecdsaPub.Curve != nil {
					switch ecdsaPub.Curve.Params().Name {
					case "P-384":
						sigScheme = 0x0503 // ecdsa_secp384r1_sha384
						coordLen = 48
					case "P-521":
						sigScheme = 0x0603 // ecdsa_secp521r1_sha512
						coordLen = 66
					default:
						sigScheme = 0x0403 // ecdsa_secp256r1_sha256
						coordLen = 32
					}
				}
				// RFC 8446 & RFC 3279: ECDSA signatures MUST be ASN.1 DER encoded SEQUENCE { r INTEGER, s INTEGER }
				rBytes := make([]byte, coordLen)
				sBytes := make([]byte, coordLen)
				_, _ = rand.Read(rBytes)
				_, _ = rand.Read(sBytes)
				rInt := new(big.Int).SetBytes(rBytes)
				sInt := new(big.Int).SetBytes(sBytes)
				if rInt.Sign() == 0 {
					rInt.SetInt64(1)
				}
				if sInt.Sign() == 0 {
					sInt.SetInt64(1)
				}
				type ecdsaSig struct {
					R, S *big.Int
				}
				cvSig, _ = asn1.Marshal(ecdsaSig{R: rInt, S: sInt})
			case x509.RSA:
				sigScheme = 0x0804 // rsa_pss_rsae_sha256
				sigLen := 256
				if rsaPub, ok := parsedCert.PublicKey.(*rsa.PublicKey); ok && rsaPub != nil {
					sigLen = rsaPub.Size()
					if sigLen == 384 {
						sigScheme = 0x0805 // rsa_pss_rsae_sha384
					} else if sigLen >= 512 {
						sigScheme = 0x0806 // rsa_pss_rsae_sha512
					}
				}
				cvSig = make([]byte, sigLen)
				_, _ = rand.Read(cvSig)
			case x509.Ed25519:
				sigScheme = 0x0807 // ed25519
				cvSig = make([]byte, 64)
				_, _ = rand.Read(cvSig)
			}
		}
	}
	if len(cvSig) == 0 {
		cvSig = make([]byte, 256)
		_, _ = rand.Read(cvSig)
	}

	var cv cryptobyte.Builder
	cv.AddUint8(0x0f)
	cv.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(sigScheme)
		b.AddUint16LengthPrefixed(func(sig *cryptobyte.Builder) {
			sig.AddBytes(cvSig)
		})
	})
	cvBytes, _ := cv.Bytes()

	// Assemble handshake records
	var hsPayload []byte
	hsPayload = append(hsPayload, eeBytes...)
	hsPayload = append(hsPayload, certBytes...)
	hsPayload = append(hsPayload, cvBytes...)

	// TH2 = Hash(ClientHello...CertificateVerify)
	th2 := sha256.Sum256(append(append(clientHelloHandshake, serverHelloHandshake...), hsPayload...))

	// Finished (0x14)
	finKey := sFinKey
	h := hmac.New(sha256.New, finKey)
	h.Write(th2[:])
	verifyData := h.Sum(nil)

	var fin cryptobyte.Builder
	fin.AddUint8(0x14) // Finished
	fin.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(verifyData)
	})
	finBytes, _ := fin.Bytes()
	hsPayload = append(hsPayload, finBytes...)

	// TH3 = Hash(ClientHello...ServerFinished) for application keys derivation
	th3 := sha256.Sum256(append(append(clientHelloHandshake, serverHelloHandshake...), hsPayload...))

	// TLS 1.3 Inner Plaintext: [handshake_messages] + [0x16]
	innerPlaintext := append(hsPayload, 0x16)

	// Encrypt with serverHandshakeKey (seq 0)
	aead, err := createTLS13AEAD(cipherSuite, serverHandshakeKey)
	if err != nil {
		return nil, th3, err
	}
	var iv [12]byte
	copy(iv[:], serverHandshakeIV)
	nonce := makeTLS13Nonce(iv, 0)

	recordLen := len(innerPlaintext) + 16
	hdr := []byte{0x17, 0x03, 0x03, byte(recordLen >> 8), byte(recordLen)}
	ciphertext := aead.Seal(nil, nonce, innerPlaintext, hdr)

	return append(hdr, ciphertext...), th3, nil
}

// buildEncryptedNewSessionTicket constructs NewSessionTicket message per RFC 8446
// and encrypts it with serverAppKey.
func buildEncryptedNewSessionTicket(cipherSuite uint16, ticketAgeAdd uint32, ticketNonce []byte, ticket []byte, serverAppKey, serverAppIV []byte, seq uint64) ([]byte, error) {
	// Randomize ticket size between 192 and 384 bytes to mimic major CDNs
	if len(ticket) == 0 || len(ticket) == 128 {
		var randLenByte [1]byte
		rand.Read(randLenByte[:])
		rndLen := 192 + int(randLenByte[0])%192 // 192..383 bytes
		ticket = make([]byte, rndLen)
		rand.Read(ticket)
	}

	var msg cryptobyte.Builder
	msg.AddUint8(0x04) // Handshake type: NewSessionTicket
	msg.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint32(604800) // ticket_lifetime: 7 days
		b.AddUint32(ticketAgeAdd)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(ticketNonce)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(ticket)
		})
		b.AddUint16(0x0000) // extensions: empty
	})
	payload, _ := msg.Bytes()
	innerPlaintext := append(payload, 0x16) // Content type 0x16 (Handshake)

	aead, err := createTLS13AEAD(cipherSuite, serverAppKey)
	if err != nil {
		return nil, err
	}
	var iv [12]byte
	copy(iv[:], serverAppIV)
	nonce := makeTLS13Nonce(iv, seq)

	recordLen := len(innerPlaintext) + 16
	hdr := []byte{0x17, 0x03, 0x03, byte(recordLen >> 8), byte(recordLen)}
	ciphertext := aead.Seal(nil, nonce, innerPlaintext, hdr)

	return append(hdr, ciphertext...), nil
}

func buildServerHello(serverRandom []byte, sessionID []byte, cipherSuite uint16, serverEphPub []byte) []byte {
	var hello cryptobyte.Builder
	hello.AddUint8(0x02) // ServerHello
	hello.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303) // legacy_version: TLS 1.2
		b.AddBytes(serverRandom)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(sessionID)
		})
		b.AddUint16(cipherSuite)
		b.AddUint8(0x00) // null compression
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			// supported_versions (0x002b) -> TLS 1.3 (0x0304)
			b.AddUint16(0x002b)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x0304)
			})
			// key_share (0x0033) -> X25519 (0x001d)
			b.AddUint16(0x0033)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x001d)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(serverEphPub)
				})
			})
		})
	})
	helloBytes, _ := hello.Bytes()

	var record cryptobyte.Builder
	record.AddUint8(0x16) // Handshake
	record.AddUint16(0x0303)
	record.AddUint16(uint16(len(helloBytes)))
	record.AddBytes(helloBytes)
	recBytes, _ := record.Bytes()
	return recBytes
}

type realitySecureConn struct {
	readHeader [5]byte
	readNonce  [12]byte
	recordBuf  wire.TLSRecordBuffer
	writeErr   error
	decBuf     []byte
	net.Conn
	encCipher          cipher.AEAD
	decCipher          cipher.AEAD
	encCipherLegacy    cipher.AEAD
	decCipherLegacy    cipher.AEAD
	encNonce           uint64
	decNonce           uint64
	encIV              [12]byte
	decIV              [12]byte
	encIVLegacy        [12]byte
	decIVLegacy        [12]byte
	firstRecordDecoded bool
	readBuf            []byte
	writeMu            sync.Mutex
	xhttpBatch         bool
	readMu             sync.Mutex
}

func newRealityConn(conn net.Conn, cipherSuite uint16, encKey, encIV, decKey, decIV, encKeyLeg, encIVLeg, decKeyLeg, decIVLeg []byte, initEncSeq, initDecSeq uint64) (*realitySecureConn, error) {
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
	}
	copy(c.encIV[:], encIV)
	copy(c.decIV[:], decIV)
	if len(encKeyLeg) > 0 && len(decKeyLeg) > 0 {
		if encLeg, err := createTLS13AEAD(cipherSuite, encKeyLeg); err == nil {
			if decLeg, err := createTLS13AEAD(cipherSuite, decKeyLeg); err == nil {
				c.encCipherLegacy = encLeg
				c.decCipherLegacy = decLeg
				copy(c.encIVLegacy[:], encIVLeg)
				copy(c.decIVLegacy[:], decIVLeg)
			}
		}
	}
	return c, nil
}

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
		if c.encNonce < 12 || chunkSize < 900 {
			var rnd [1]byte
			_, _ = rand.Read(rnd[:])
			padLen = 16 + int(rnd[0])%112 // 16..127 bytes random RFC 8446 padding
			if chunkSize+1+padLen > maxPlaintext {
				padLen = 0
			}
		}

		// RFC 8446 Section 5.4: TLSInnerPlaintext wraps content with trailing ContentType (0x17) and padding zeros
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

	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		// Clear slice to allow GC when buffer is drained
		if len(c.readBuf) == 0 {
			c.readBuf = nil
		}
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

	var dst []byte
	if c.firstRecordDecoded || c.decCipherLegacy == nil {
		dst = cipherBuf[:0]
	}
	plaintext, err := c.decCipher.Open(dst, nonce, cipherBuf, header[:])
	if err != nil && !c.firstRecordDecoded && c.decCipherLegacy != nil {
		legNonce := makeTLS13Nonce(c.decIVLegacy, c.decNonce-1)
		if ptLeg, errLeg := c.decCipherLegacy.Open(nil, legNonce, cipherBuf, header[:]); errLeg == nil {
			plaintext = ptLeg
			err = nil
			c.decCipher = c.decCipherLegacy
			c.decIV = c.decIVLegacy
			c.writeMu.Lock()
			c.encCipher = c.encCipherLegacy
			c.encIV = c.encIVLegacy
			c.writeMu.Unlock()
			log.Printf("[REALITY] Client %s auto-negotiated legacy HKDF master secret", c.Conn.RemoteAddr())
		}
	}
	c.firstRecordDecoded = true
	if err != nil {
		return 0, fmt.Errorf("AEAD decrypt failed: %w", err)
	}

	// RFC 8446 Section 5.4: strip trailing ContentType (0x17) and padding zeros
	if len(plaintext) == 0 {
		return 0, fmt.Errorf("TLS 1.3 inner plaintext is empty")
	}
	padIdx := len(plaintext) - 1
	for padIdx >= 0 && plaintext[padIdx] == 0 {
		padIdx--
	}
	if padIdx < 0 || plaintext[padIdx] != 0x17 {
		return 0, fmt.Errorf("TLS 1.3 inner plaintext missing or invalid content type")
	}
	plaintext = plaintext[:padIdx]

	n := copy(p, plaintext)
	if n < len(plaintext) {
		// The read lock drains this view before the backing buffer is reused.
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

type tcpListenerRuntime struct {
	config     *Config
	identity   *ecdh.PrivateKey
	tcp        bool
	xhttp      bool
	legacyPath bool
}

func handleFork(conn net.Conn) {
	runtime := &tcpListenerRuntime{config: cfg, identity: serverStaticECDH, tcp: true, xhttp: true, legacyPath: true}
	runtime.handleFork(conn)
}

func (r *tcpListenerRuntime) proxyDecoy(ctx context.Context, conn net.Conn, initial []byte) {
	if ctx.Err() != nil {
		_ = conn.Close()
		return
	}
	proxyDecoyToContext(ctx, conn, r.config.GetSNI(), initial)
}

func (r *tcpListenerRuntime) handleFork(conn net.Conn) {
	r.handleForkContext(context.Background(), conn)
}

func (r *tcpListenerRuntime) handleForkContext(ctx context.Context, conn net.Conn) {
	cfg := r.config
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in handleFork: %v", r)
			conn.Close()
		}
	}()

	bufConn := &bufferedConn{Conn: conn}

	raw, clientHelloHandshake, readErr := readClientHelloFlight(conn, 30*time.Second)
	bufConn.buf = raw
	if readErr != nil {
		if len(raw) == 0 {
			conn.Close()
		} else {
			r.proxyDecoy(ctx, bufConn, raw)
		}
		return
	}

	// Parse ClientHello
	sni, alpn, sessionID, clientRandom, clientPubKey, offeredSuites, err := parseClientHelloInfo(bufConn.buf)
	targetSNI := cfg.GetSNI()

	// Proxy to decoy on parse failure
	if err != nil {
		log.Printf("[DECOY] ClientHello parse failed from %s: %v", conn.RemoteAddr(), err)
		r.proxyDecoy(ctx, bufConn, bufConn.buf)
		return
	}

	// Reality authorization check
	if authUser, userPBK, _, isV3, isReplay, ok, wireVersion := authenticateSessionIDWithIdentity(cfg, r.identity, sessionID, clientPubKey, clientHelloHandshake); ok {
		if !isUserAllowed(authUser) || !inboundUserAllowed(cfg.InboundID, authUser) {
			log.Printf("[VPN] Reality user '%s' rejected (disabled, expired, or quota reached). Routing to decoy %s", authUser, targetSNI)
			r.proxyDecoy(ctx, bufConn, bufConn.buf)
			return
		}
		log.Printf("[VPN] Reality client authorized: %s (user: %s, isV3: %v)", conn.RemoteAddr(), authUser, isV3)
		if _, supported := chooseRealityCipher(offeredSuites, isV3); !supported {
			r.proxyDecoy(ctx, bufConn, bufConn.buf)
			return
		}
		bufConn.buf = nil
		r.handleVPNReality(bufConn, targetSNI, userPBK, clientRandom, clientPubKey, sessionID, clientHelloHandshake, alpn, authUser, isV3, offeredSuites, wireVersion)
		return
	} else if isReplay {
		// A replay must not open another VPN session. Relay the original bytes
		// to the configured donor; this does not guarantee identical timing.
		log.Printf("[SECURITY] Replayed ClientHello from %s (SNI=%s); forwarding to donor %s", conn.RemoteAddr(), sni, targetSNI)
		r.proxyDecoy(ctx, bufConn, bufConn.buf)
		return
	}

	// XHTTP check (if certificate configured)
	if r.xhttp && cfg.WireVersion != 4 && cfg.WireVersion != 6 && cfg.WireVersion != 7 && cfg.LegacyWire && cfg.CertFile != "" && cfg.KeyFile != "" && (cfg.Transport == "xhttp" || cfg.Transport == "auto") {
		handleXHTTPConfigured(bufConn, cfg)
		return
	}

	// Transparent proxy to decoy target
	log.Printf("[DECOY] Unauthorized/probe from %s (SNI=%s, pubKeyLen=%d, sessIDLen=%d). Transparent proxy to genuine donor %s", conn.RemoteAddr(), sni, len(clientPubKey), len(sessionID), targetSNI)
	r.proxyDecoy(ctx, bufConn, bufConn.buf)
}

func (r *tcpListenerRuntime) handleVPNReality(clientConn net.Conn, targetSNI string, userPBK string, clientRandom []byte, clientPubKey []byte, sessionID []byte, clientHelloHandshake []byte, clientALPN []string, authUser string, isV3 bool, offeredSuites []uint16, wireVersion int) {
	cfg := r.config
	defer clientConn.Close()
	// The donor is an operator-controlled destination, never a client-supplied SNI.
	targetSNI = cfg.GetSNI()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in handleVPNReality: %v", r)
			clientConn.Close()
		}
	}()

	if len(clientPubKey) != 32 {
		log.Printf("[REALITY] Client %s did not provide valid 32-byte X25519 key share", clientConn.RemoteAddr())
		clientConn.Close()
		return
	}

	// Normalize RFC 8446 transcript: handshake payload starts with 0x01 (ClientHello)
	// without 5-byte TLS record header (0x16 0x03 0x03 ...)
	if len(clientHelloHandshake) > 5 && clientHelloHandshake[0] == 0x16 && clientHelloHandshake[1] == 0x03 {
		clientHelloHandshake = clientHelloHandshake[5:]
	}

	// Negotiate TLS 1.3 cipher suite:
	// For V3 clients, prefer TLS_AES_128_GCM_SHA256 (0x1301) to match real Chrome/Microsoft CDNs and hardware AES-NI.
	// For legacy clients, fallback to TLS_CHACHA20_POLY1305_SHA256 (0x1303).
	chosenCipherSuite, supported := chooseRealityCipher(offeredSuites, isV3)
	if !supported {
		// The current server key schedule is SHA-256. Never select 0x1302
		// (SHA-384) or an unoffered suite and emit an invalid TLS handshake.
		clientConn.Close()
		return
	}

	// Generate ephemeral X25519 keypair
	curve := ecdh.X25519()
	serverEphPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("[REALITY] Failed to generate server X25519 key: %v", err)
		clientConn.Close()
		return
	}
	serverEphPub := serverEphPriv.PublicKey().Bytes()

	// Compute shared secret: sharedSecret = ECDH(ServerPriv, ClientPub)
	clientPeerKey, err := curve.NewPublicKey(clientPubKey)
	if err != nil {
		log.Printf("[REALITY] Invalid client X25519 public key: %v", err)
		clientConn.Close()
		return
	}
	sharedSecret, err := serverEphPriv.ECDH(clientPeerKey)
	if err != nil {
		log.Printf("[REALITY] ECDH computation failed: %v", err)
		clientConn.Close()
		return
	}

	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)

	// Build TLS 1.3 ServerHello with negotiated cipherSuite (0x1301 or 0x1303)
	serverHelloRecord := buildServerHello(serverRandom, sessionID, chosenCipherSuite, serverEphPub)

	// Derive TLS 1.3 handshake keys via TH1 = Hash(ClientHello || ServerHello)
	serverHelloHandshake := serverHelloRecord[5:]
	th1 := sha256.Sum256(append(clientHelloHandshake, serverHelloHandshake...))

	// 2-ECDH: static ECDH secret computation for Finished authentication
	var staticShared []byte
	if r.identity != nil {
		if ss, err := r.identity.ECDH(clientPeerKey); err == nil {
			staticShared = ss
		}
	}

	cHsKey, cHsIV, sHsKey, sHsIV, cFinKey, sFinKey, masterSecret, masterSecretLegacy := deriveTLS13HandshakeKeys(sharedSecret, staticShared, th1[:], chosenCipherSuite)

	// ALPN negotiation: match client ALPN preference (RFC 8446 Section 4.2: do NOT send ALPN if client offered none)
	selectedALPN := ""
	if len(clientALPN) > 0 {
		hasH2 := false
		for _, proto := range clientALPN {
			if proto == "h2" {
				hasH2 = true
				break
			}
		}
		if hasH2 {
			selectedALPN = "h2"
		} else {
			selectedALPN = clientALPN[0]
		}
	}

	// Encrypt the server handshake and bind Finished to the transcript.
	// Server Finished verify_data is calculated over transcript TH2 = Hash(CH...CV)
	// Returns TH3 = Hash(CH...ServerFinished)
	hsRecord, th3, err := buildEncryptedServerHandshake(targetSNI, chosenCipherSuite, sHsKey, sHsIV, sFinKey, clientHelloHandshake, serverHelloHandshake, selectedALPN)
	if err != nil {
		log.Printf("[REALITY] Failed to build encrypted handshake: %v", err)
		clientConn.Close()
		return
	}

	// Send ServerHello + ChangeCipherSpec + EncryptedHandshake in a SINGLE TCP flight!
	// Coalescing eliminates the isolated 6-byte ChangeCipherSpec packet (eliminates DPI signature).
	ccsRecord := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	fullFlight := make([]byte, 0, len(serverHelloRecord)+len(ccsRecord)+len(hsRecord))
	fullFlight = append(fullFlight, serverHelloRecord...)
	fullFlight = append(fullFlight, ccsRecord...)
	fullFlight = append(fullFlight, hsRecord...)

	if _, err := clientConn.Write(fullFlight); err != nil {
		log.Printf("[REALITY] Failed to send handshake flight to %s: %v", clientConn.RemoteAddr(), err)
		clientConn.Close()
		return
	}

	// Derive application traffic keys from TH3 = Hash(ClientHello...ServerFinished)
	cAppKey, cAppIV, sAppKey, sAppIV := deriveTLS13AppKeys(masterSecret, th3[:], chosenCipherSuite)
	cAppKeyLeg, cAppIVLeg, sAppKeyLeg, sAppIVLeg := deriveTLS13AppKeys(masterSecretLegacy, th3[:], chosenCipherSuite)

	// Read client Finished (0x17) with optional ChangeCipherSpec (0x14) per RFC 8446
	clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	firstHdr := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, firstHdr); err != nil {
		log.Printf("[REALITY] Failed to read client record header from %s: %v", clientConn.RemoteAddr(), err)
		clientConn.Close()
		return
	}

	finHdr := firstHdr
	if firstHdr[0] == 0x14 {
		// Client sent ChangeCipherSpec (middlebox_compatibility_mode)
		ccsLen := int(binary.BigEndian.Uint16(firstHdr[3:5]))
		if ccsLen > 0 && ccsLen <= 16 {
			ccsPayload := make([]byte, ccsLen)
			if _, err := io.ReadFull(clientConn, ccsPayload); err != nil {
				log.Printf("[REALITY] Failed to read client CCS payload from %s: %v", clientConn.RemoteAddr(), err)
				clientConn.Close()
				return
			}
		}
		// Read Finished record (0x17)
		finHdr = make([]byte, 5)
		if _, err := io.ReadFull(clientConn, finHdr); err != nil {
			log.Printf("[REALITY] Failed to read client Finished header from %s: %v", clientConn.RemoteAddr(), err)
			clientConn.Close()
			return
		}
	}

	if finHdr[0] != 0x17 {
		log.Printf("[REALITY] Unexpected client Finished record type: 0x%02x (expected 0x17)", finHdr[0])
		clientConn.Close()
		return
	}

	finLen := int(binary.BigEndian.Uint16(finHdr[3:5]))
	if finLen < 16 || finLen > 16384+256 {
		log.Printf("[REALITY] Invalid client Finished length: %d", finLen)
		clientConn.Close()
		return
	}
	finCipher := make([]byte, finLen)
	if _, err := io.ReadFull(clientConn, finCipher); err != nil {
		log.Printf("[REALITY] Failed to read client Finished payload from %s: %v", clientConn.RemoteAddr(), err)
		clientConn.Close()
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	// Authenticate client Finished record with clientHandshakeKey (seq 0)
	cAead, err := createTLS13AEAD(chosenCipherSuite, cHsKey)
	if err != nil {
		clientConn.Close()
		return
	}
	var cIV [12]byte
	copy(cIV[:], cHsIV)
	nonce := makeTLS13Nonce(cIV, 0)
	finPlaintext, err := cAead.Open(nil, nonce, finCipher, finHdr)
	if err != nil {
		log.Printf("[REALITY] Client Finished AEAD authentication failed from %s: %v", clientConn.RemoteAddr(), err)
		clientConn.Close()
		return
	}
	if len(finPlaintext) < 1 || finPlaintext[len(finPlaintext)-1] != 0x16 {
		log.Printf("[REALITY] Invalid client Finished inner plaintext type")
		clientConn.Close()
		return
	}

	// Verify TLS 1.3 Finished verify_data over transcript TH3 = Hash(ClientHello...ServerFinished)
	finMsg := finPlaintext[:len(finPlaintext)-1]
	if len(finMsg) < 4+32 || finMsg[0] != 0x14 {
		log.Printf("[REALITY] Malformed client Finished message from %s (len=%d)", clientConn.RemoteAddr(), len(finMsg))
		clientConn.Close()
		return
	}
	cMac := hmac.New(sha256.New, cFinKey)
	cMac.Write(th3[:])
	expectedVerifyData := cMac.Sum(nil)
	if !hmac.Equal(finMsg[4:4+32], expectedVerifyData) {
		log.Printf("[REALITY] Client Finished verify_data mismatch from %s", clientConn.RemoteAddr())
		clientConn.Close()
		return
	}

	if wireVersion == 6 || wireVersion == 7 {
		if !consumeAuthToken(realityReplayKey(wireVersion, sessionID, clientPubKey)) {
			clientConn.Close()
			return
		}
	}

	// Send NewSessionTicket records encrypted with sAppKey (seq 0 and 1) strictly AFTER ClientFinished (RFC 8446 Section 4.6.1)
	var nonce1 [8]byte
	var nonce2 [8]byte
	_, _ = rand.Read(nonce1[:])
	_, _ = rand.Read(nonce2[:])
	age1 := uint32(time.Now().UnixNano()%100000 + 100)
	age2 := uint32(time.Now().UnixNano()%100000 + 200)

	t1, err := buildEncryptedNewSessionTicket(chosenCipherSuite, age1, nonce1[:], nil, sAppKey, sAppIV, 0)
	if err != nil {
		clientConn.Close()
		return
	}
	t2, err := buildEncryptedNewSessionTicket(chosenCipherSuite, age2, nonce2[:], nil, sAppKey, sAppIV, 1)
	if err != nil {
		clientConn.Close()
		return
	}
	if _, err := clientConn.Write(append(t1, t2...)); err != nil {
		clientConn.Close()
		return
	}

	// Wrap connection in TLS 1.3 record AEAD layer (AES-128-GCM or ChaCha20-Poly1305)
	// Server encrypts with sAppKey (seq 2+), decrypts with cAppKey (seq 0+)
	if wireVersion == 4 || (wireVersion == 6 || wireVersion == 7) {
		sAppKeyLeg, sAppIVLeg, cAppKeyLeg, cAppIVLeg = nil, nil, nil, nil
	}
	secureConn, err := newRealityConn(clientConn, chosenCipherSuite, sAppKey, sAppIV, cAppKey, cAppIV, sAppKeyLeg, sAppIVLeg, cAppKeyLeg, cAppIVLeg, 2, 0)
	if err != nil {
		log.Printf("[REALITY] Failed to initialize secure conn: %v", err)
		clientConn.Close()
		return
	}

	log.Printf("[REALITY] Full TLS 1.3 Genuine Cryptographic Handshake completed with %s (Mutual AEAD Verified + verify_data OK)",
		clientConn.RemoteAddr())
	if !inboundUserAllowed(cfg.InboundID, authUser) {
		return
	}

	// Peek initial bytes for protocol dispatch
	peek := make([]byte, 4)
	secureConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := io.ReadFull(secureConn, peek)
	secureConn.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("[REALITY] Failed to peek stream protocol from %s: %v", clientConn.RemoteAddr(), err)
		secureConn.Close()
		return
	}

	duplexConn := &bufferedConn{
		Conn: secureConn,
		buf:  peek[:n],
	}

	if string(peek) == "PRI " {
		if !r.xhttp {
			return
		}
		log.Printf("[REALITY] Auto-detected native HTTP/2 (XHTTP) from %s", clientConn.RemoteAddr())
		handleBoundXHTTPServer(duplexConn, cfg.Path, r.legacyPath, authUser, cfg.InboundID)
		return
	}
	if !r.tcp {
		return
	}

	if peek[0] == 0x00 {
		log.Printf("[REALITY] Auto-detected Yamux multiplexed session from %s", clientConn.RemoteAddr())
		yCfg := inboundYamuxConfig(cfg)

		sess, err := yamux.Server(duplexConn, yCfg)
		if err != nil {
			log.Printf("[REALITY] Yamux server init failed from %s: %v", clientConn.RemoteAddr(), err)
			duplexConn.Close()
			return
		}
		defer sess.Close()

		for {
			stream, err := sess.Accept()
			if err != nil {
				log.Printf("[REALITY] Yamux session ended from %s: %v", clientConn.RemoteAddr(), err)
				break
			}
			go handleStream(stream, authUser, wireVersion, cfg.InboundID)
		}
		return
	}

	log.Printf("[REALITY] Direct 1-to-1 connection established from %s (Zero-Yamux overhead)", clientConn.RemoteAddr())
	handleStream(duplexConn, authUser, wireVersion, cfg.InboundID)
}

// Keep the XHTTP-only write policy reachable through the protocol-peek wrapper.
func (b *bufferedConn) enableXHTTPBatching() {
	if conn, ok := b.Conn.(interface{ enableXHTTPBatching() }); ok {
		conn.enableXHTTPBatching()
	}
}

func handleStream(stream net.Conn, authUser string, wireVersion int, inboundID ...string) {
	defer stream.Close()
	cleanup, sessionErr := reserveUserSession(authUser, stream.RemoteAddr().String(), func() {
		_ = stream.Close()
	})
	if sessionErr != nil {
		return
	}
	defer cleanup()
	if len(inboundID) > 0 && !inboundUserAllowed(inboundID[0], authUser) {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in handleStream: %v", r)
			stream.Close()
		}
	}()
	// Set 15-second deadline for stream metadata read to prevent Slowloris leak
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))

	// Protocol type:
	// 0x01 = TCP, 0x02 = UDP
	// 0x11 = TCP with padding, 0x12 = UDP with padding
	protoBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, protoBuf); err != nil {
		return
	}
	protocol := protoBuf[0]
	if protocol == 0x15 {
		if wireVersion == 6 {
			serveBoundRealityAdmission(stream, authUser, wireVersion)
		}
		return
	}
	if protocol == 0x14 {
		serveBoundRealityAdmission(stream, authUser, wireVersion)
		return
	}
	if protocol == 0x13 {
		serveRealityAdmission(stream, authUser, wireVersion)
		return
	}
	if protocol != 0x01 && protocol != 0x02 && protocol != 0x11 && protocol != 0x12 {
		return
	}

	// Read the destination address from the client: [2-byte length][address string]
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	addrLen := int(lenBuf[0])<<8 | int(lenBuf[1])

	if addrLen <= 0 || addrLen > 512 { // Support long FQDNs and align with QUIC streams
		log.Printf("[STREAM] Invalid address length: %d bytes", addrLen)
		return
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(stream, addrBuf); err != nil {
		return
	}
	addr := string(addrBuf)

	// Dynamic padding handling (DPI packet size obfuscation)
	if protocol == 0x11 || protocol == 0x12 {
		padLenBuf := make([]byte, 2)
		if _, err := io.ReadFull(stream, padLenBuf); err != nil {
			return
		}
		padLen := int(padLenBuf[0])<<8 | int(padLenBuf[1])
		if padLen > 0 && padLen <= 4096 {
			if _, err := io.CopyN(io.Discard, stream, int64(padLen)); err != nil {
				return
			}
		}
		if protocol == 0x11 {
			protocol = 0x01
		} else {
			protocol = 0x02
		}
	}

	// Chaffing / keepalive micro-pulse: stream opened, header & padding consumed, return gracefully
	if addr == "127.0.0.1:0" || addr == "chaffing" || addr == "keepalive" {
		return
	}

	// Reset read deadline for active data streaming
	_ = stream.SetReadDeadline(time.Time{})

	if protocol == 0x02 { // UDP
		log.Printf("[STREAM-UDP] Proxy to %s", addr)
		udpAddr, err := safeResolveUDP(addr)
		if err != nil {
			log.Printf("[STREAM-UDP] Failed to resolve %s: %v", addr, err)
			return
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Printf("[STREAM-UDP] Failed to dial %s: %v", addr, err)
			return
		}
		defer conn.Close()

		var wg sync.WaitGroup
		var once sync.Once
		wg.Add(2)

		// stream -> dest (length-prefixed)
		go func() {
			defer wg.Done()
			defer once.Do(func() { conn.Close(); stream.Close() })
			lenBuf := make([]byte, 2)
			for {
				_ = stream.SetReadDeadline(time.Now().Add(300 * time.Second))
				if _, err := io.ReadFull(stream, lenBuf); err != nil {
					return
				}
				length := binary.BigEndian.Uint16(lenBuf)
				if length > 65507 {
					log.Printf("[STREAM-UDP] Packet too large: %d bytes", length)
					return
				}
				buf := make([]byte, length)
				if _, err := io.ReadFull(stream, buf); err != nil {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
				if !recordUserTraffic(authUser, uint64(len(buf)), 0) {
					return
				}
				if _, err := conn.Write(buf); err != nil {
					return
				}
			}
		}()

		// dest -> stream (length-prefixed)
		go func() {
			defer wg.Done()
			defer once.Do(func() { conn.Close(); stream.Close() })
			buf := make([]byte, 2+65507)
			var emptyCycles int
			const maxEmptyCycles = 150 // 150 * 2s = 300s (5 minutes idle timeout per standard UDP NAT)

			for {
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := conn.Read(buf[2:])
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						emptyCycles++
						if emptyCycles >= maxEmptyCycles {
							log.Printf("[STREAM-UDP] Stream timeout after %d empty cycles", emptyCycles)
							return
						}
						continue
					}
					return
				}

				emptyCycles = 0
				response := dnsUDPResponse(addr, buf[2:2+n])
				n = copy(buf[2:], response)
				if !recordUserTraffic(authUser, 0, uint64(n)) {
					return
				}
				binary.BigEndian.PutUint16(buf[:2], uint16(n))
				_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := writeFull(stream, buf[:2+n]); err != nil {
					return
				}
			}
		}()
		wg.Wait()
		return
	}

	// TCP (0x01)
	log.Printf("[STREAM-TCP] Proxy to %s", addr)

	if isSpeedtestAddr(addr) {
		handleSpeedtestStream(stream, authUser)
		return
	}

	// Dial destination with DNS-rebinding and SSRF protection
	destConn, err := safeDialTCP(addr, 10*time.Second)
	if err != nil {
		log.Printf("[STREAM-TCP] Failed to dial %s: %v", addr, err)
		return
	}
	defer destConn.Close()

	var wg sync.WaitGroup
	var once sync.Once
	wg.Add(2)

	closeBoth := func() {
		_ = destConn.Close()
		_ = stream.Close()
	}

	const idleTimeout = 5 * time.Minute

	copyHalf := func(dst, src net.Conn, isUpload bool) {
		defer wg.Done()
		buf := make([]byte, 65536)
		var readIdle, writeIdle wire.IdleDeadline
		for {
			_ = readIdle.Update(time.Now(), idleTimeout, src.SetReadDeadline)
			n, err := src.Read(buf)
			if n > 0 {
				if isUpload {
					if !recordUserTraffic(authUser, uint64(n), 0) {
						once.Do(closeBoth)
						return
					}
				} else {
					if !recordUserTraffic(authUser, 0, uint64(n)) {
						once.Do(closeBoth)
						return
					}
				}
				_ = writeIdle.Update(time.Now(), idleTimeout, dst.SetWriteDeadline)
				if wErr := writeFull(dst, buf[:n]); wErr != nil {
					once.Do(closeBoth)
					return
				}
			}
			if err != nil {
				if isUpload {
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
					_ = dst.SetReadDeadline(time.Now().Add(idleTimeout))
				} else {
					once.Do(closeBoth)
				}
				return
			}
		}
	}

	go copyHalf(destConn, stream, true)
	go copyHalf(stream, destConn, false)

	wg.Wait()
	once.Do(closeBoth)
}

type bufferedConn struct {
	net.Conn
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

// Clean TLS ClientHello parser extracting SNI, standard ALPN protocols, raw SessionID, clientRandom, clientPubKey (X25519) and offered cipher suites.
// Supports both single TLS records and fragmented ClientHello spanning multiple consecutive TLS records.
func parseClientHelloInfo(data []byte) (sni string, alpnProtos []string, sessionID []byte, clientRandom []byte, clientPubKey []byte, offeredSuites []uint16, err error) {
	if len(data) < 5 || len(data) > maxClientHelloWireBytes {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("data too short for TLS record: %d bytes", len(data))
	}

	// Aggregate consecutive TLS record payloads (TLS Record Fragmentation)
	var handshakeData []byte
	offset := 0
	for offset < len(data) {
		if offset+5 > len(data) {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("truncated TLS record header at offset %d: %d bytes left", offset, len(data)-offset)
		}
		if data[offset] != 0x16 {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("not TLS handshake record at offset %d: 0x%02x", offset, data[offset])
		}
		recLen := int(data[offset+3])<<8 | int(data[offset+4])
		if recLen < 1 || recLen > 16384 {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("invalid TLS record length at offset %d: %d", offset, recLen)
		}
		if offset+5+recLen > len(data) {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("truncated TLS record: expected %d bytes, got %d", offset+5+recLen, len(data))
		}
		handshakeData = append(handshakeData, data[offset+5:offset+5+recLen]...)
		offset += 5 + recLen
	}

	if len(handshakeData) < 4 {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("handshake payload too short: %d bytes", len(handshakeData))
	}
	if handshakeData[0] != 0x01 { // ClientHello
		return "", nil, nil, nil, nil, nil, fmt.Errorf("not ClientHello message type: 0x%02x", handshakeData[0])
	}
	handshakeLen := int(handshakeData[1])<<16 | int(handshakeData[2])<<8 | int(handshakeData[3])
	if len(handshakeData) != 4+handshakeLen {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("truncated ClientHello handshake message: expected %d bytes, got %d", 4+handshakeLen, len(handshakeData))
	}

	clientHello := cryptobyte.String(handshakeData[4 : 4+handshakeLen])
	var clientVersion uint16
	var randomBytes []byte
	var sessionId cryptobyte.String
	var cipherSuites, compressionMethods cryptobyte.String
	var extensions cryptobyte.String

	if !clientHello.ReadUint16(&clientVersion) ||
		!clientHello.ReadBytes(&randomBytes, 32) ||
		!clientHello.ReadUint8LengthPrefixed(&sessionId) {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("failed to parse ClientHello structure")
	}
	if len(sessionId) > 32 {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("ClientHello session ID exceeds 32 bytes")
	}

	sessionIDBytes := make([]byte, len(sessionId))
	copy(sessionIDBytes, sessionId)
	clientRandom = make([]byte, 32)
	copy(clientRandom, randomBytes)

	if !clientHello.ReadUint16LengthPrefixed(&cipherSuites) ||
		!clientHello.ReadUint8LengthPrefixed(&compressionMethods) ||
		!clientHello.ReadUint16LengthPrefixed(&extensions) {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("failed to parse remaining ClientHello structure")
	}
	if !clientHello.Empty() || len(cipherSuites) == 0 || len(cipherSuites)%2 != 0 || len(compressionMethods) != 1 || compressionMethods[0] != 0 {
		return "", nil, nil, nil, nil, nil, fmt.Errorf("invalid ClientHello vectors")
	}

	for !cipherSuites.Empty() {
		var cs uint16
		if !cipherSuites.ReadUint16(&cs) {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("truncated cipher suite")
		}
		offeredSuites = append(offeredSuites, cs)
	}

	seenExtensions := make(map[uint16]bool)
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String

		if !extensions.ReadUint16(&extType) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("truncated ClientHello extension")
		}
		if seenExtensions[extType] {
			return "", nil, nil, nil, nil, nil, fmt.Errorf("duplicate ClientHello extension")
		}
		seenExtensions[extType] = true

		switch extType {
		case 0: // SNI (RFC 6066)
			var sniList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sniList) {
				continue
			}
			for !sniList.Empty() {
				var nameType uint8
				var sniName cryptobyte.String
				if !sniList.ReadUint8(&nameType) ||
					!sniList.ReadUint16LengthPrefixed(&sniName) {
					break
				}
				if nameType == 0 { // host_name
					sni = string(sniName)
					break
				}
			}

		case 16: // ALPN (strictly standard browser values: h2, http/1.1)
			var alpnList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&alpnList) {
				continue
			}
			for !alpnList.Empty() {
				var protocol cryptobyte.String
				if !alpnList.ReadUint8LengthPrefixed(&protocol) {
					break
				}
				alpnProtos = append(alpnProtos, string(protocol))
			}

		case 51: // key_share (0x0033) RFC 8446
			var clientShares cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&clientShares) {
				continue
			}
			for !clientShares.Empty() {
				var group uint16
				var keyExchange cryptobyte.String
				if !clientShares.ReadUint16(&group) ||
					!clientShares.ReadUint16LengthPrefixed(&keyExchange) {
					break
				}
				if group == 0x001d && len(keyExchange) == 32 { // Group X25519
					clientPubKey = make([]byte, 32)
					copy(clientPubKey, keyExchange)
					break
				}
			}
		}
	}

	return sni, alpnProtos, sessionIDBytes, clientRandom, clientPubKey, offeredSuites, nil
}

// isSafeIP checks IP address against SSRF (blocks loopback, link-local, private RFC 1918, IPv6 ULA, cloud metadata).
func isSafeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Normalize IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) to 4-byte representation
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	// AWS / Hetzner / GCP Cloud Metadata API (169.254.169.254)
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10)
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 0 || ip4[0] >= 240 || (ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) {
			return false
		}
		if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
			return false
		}
	}
	return true
}

// safeResolveTCP resolves host, checks all returned IPs for SSRF, and returns a verified target string.
func safeResolveTCP(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}
	// Fast-path: if host is already an IP address, validate immediately without DNS query
	if ip := net.ParseIP(host); ip != nil {
		if !isSafeIP(ip) {
			return "", fmt.Errorf("SSRF blocked: forbidden IP %s", ip)
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	var validIPs []net.IP
	for _, ip := range ips {
		if isSafeIP(ip) {
			validIPs = append(validIPs, ip)
		}
	}
	if len(validIPs) == 0 {
		return "", fmt.Errorf("SSRF blocked: all resolved IPs forbidden for host %s", host)
	}
	// Prefer IPv4 if available to avoid IPv6 unreachable errors on VPS hosts without IPv6 egress
	for _, ip := range validIPs {
		if ip.To4() != nil {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}
	// Connect to first verified IP, preventing DNS rebinding
	return net.JoinHostPort(validIPs[0].String(), port), nil
}

// isSafeDestination validates destination target against SSRF.
func isSafeDestination(target string) bool {
	_, err := safeResolveTCP(target)
	return err == nil
}

// safeDialTCP bounds DNS and all verified-address attempts by one deadline.
func safeDialTCP(target string, timeout time.Duration) (net.Conn, error) {
	return safeDialTCPContext(context.Background(), target, timeout)
}

func safeDialTCPContext(parent context.Context, target string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialPublicTCP(ctx, target, net.DefaultResolver.LookupIP, dialer.DialContext)
	if err == nil && dnsIPv4PolicyEnabled(target) {
		return &dnsPolicyTCPConn{Conn: conn}, nil
	}
	return conn, err
}

// safeResolveUDP resolves host, validates against SSRF, and returns a verified *net.UDPAddr.
func safeResolveUDP(target string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP target %s: %w", target, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP port %s: %w", portStr, err)
	}
	// Fast-path: if host is already an IP address, validate immediately without DNS query
	if ip := net.ParseIP(host); ip != nil {
		if !isSafeIP(ip) {
			return nil, fmt.Errorf("SSRF blocked: forbidden IP %s", ip)
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	var validIPs []net.IP
	for _, ip := range ips {
		if isSafeIP(ip) {
			validIPs = append(validIPs, ip)
		}
	}
	if len(validIPs) == 0 {
		return nil, fmt.Errorf("SSRF blocked: all resolved IPs forbidden for host %s", host)
	}
	for _, ip := range validIPs {
		if ip.To4() != nil {
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}
	return &net.UDPAddr{IP: validIPs[0], Port: port}, nil
}
