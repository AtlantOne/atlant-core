package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

func parsePBKBytes(pbk string) []byte {
	b, err := hex.DecodeString(pbk)
	if err == nil && len(b) == 32 {
		return b
	}
	h := sha256.Sum256([]byte(pbk))
	return h[:]
}

// RFC 8446 HKDF-Expand-Label implementation for standard TLS 1.3 key schedule
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 " + label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	labelBytes, _ := hkdfLabel.Bytes()
	out := make([]byte, length)
	kdf := hkdf.Expand(sha256.New, secret, labelBytes)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic(err)
	}
	return out
}

var (
	donorCertMu      sync.RWMutex
	donorCertChains  = make(map[string][][]byte)
	clonedQuicCerts  = make(map[string]*tls.Certificate)
	sniInitOnceMap   sync.Map // key: sni -> *sync.Once
	donorCertChain   [][]byte // legacy alias
	serverRSAPrivKey *rsa.PrivateKey
	serverCertDER    []byte
	rsaKeyOnce       sync.Once

	// Server static X25519 key for Reality 2-ECDH mutual authentication
	serverStaticECDH      *ecdh.PrivateKey
	serverStaticPubHexStr string
	serverStaticKeyOnce   sync.Once
	serverStaticKeyErr    error
)

// initServerStaticKey loads or generates the server's static X25519 key pair.
func initServerStaticKey(keyFile string) error {
	serverStaticKeyOnce.Do(func() {
		priv, err := loadOrCreateStaticKey(keyFile)
		if err != nil {
			serverStaticKeyErr = err
			return
		}
		serverStaticECDH = priv
		serverStaticPubHexStr = hex.EncodeToString(priv.PublicKey().Bytes())
		log.Printf("[REALITY] Server identity loaded: server_pub_key=%s", serverStaticPubHexStr)
	})
	return serverStaticKeyErr
}

// getServerStaticPubHex returns the hex-encoded server static X25519 public key
func getServerStaticPubHex() string {
	return serverStaticPubHexStr
}

func fetchDonorCertificateChain(sni string) [][]byte {
	if sni == "" {
		sni = "www.microsoft.com"
	}
	conf := &tls.Config{
		ServerName: sni,
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(sni, "443"), conf)
	if err != nil {
		log.Printf("[REALITY] Warning: could not fetch genuine donor cert from %s: %v", sni, err)
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var chain [][]byte
	for _, cert := range state.PeerCertificates {
		chain = append(chain, cert.Raw)
	}
	if len(chain) > 0 {
		log.Printf("[REALITY] Fetched %d genuine donor certificates from %s (Subject: %s, Issuer: %s)",
			len(chain), sni, state.PeerCertificates[0].Subject.CommonName, state.PeerCertificates[0].Issuer.CommonName)
	}
	return chain
}

func getServerObfKey(sni string) []byte {
	// Derive secret key from server static X25519 key (Reality secret), never from public SNI
	var secretSource []byte
	if serverStaticECDH != nil {
		secretSource = serverStaticECDH.PublicKey().Bytes()
	} else if serverStaticPubHexStr != "" {
		if b, err := hex.DecodeString(serverStaticPubHexStr); err == nil && len(b) == 32 {
			secretSource = b
		}
	}
	if len(secretSource) == 0 {
		// Fallback to SNI only if static key is not yet initialized
		if sni == "" {
			sni = "www.microsoft.com"
		}
		secretSource = []byte(sni)
	}
	return hkdfExpandLabel(secretSource, "server udp obf key v2", nil, 32)
}

func ensureRSAKey() {
	rsaKeyOnce.Do(func() {
		if priv, err := rsa.GenerateKey(rand.Reader, 2048); err == nil {
			serverRSAPrivKey = priv
		}
	})
}

func initServerKeys(sni string) {
	if sni == "" {
		sni = "www.microsoft.com"
	}
	ensureRSAKey()

	val, _ := sniInitOnceMap.LoadOrStore(sni, &sync.Once{})
	once := val.(*sync.Once)
	once.Do(func() {
		fallbackCert := generateValidASN1Cert(sni)
		if fallbackCert != nil {
			donorCertMu.Lock()
			donorCertChains[sni] = [][]byte{fallbackCert}
			if serverCertDER == nil {
				serverCertDER = fallbackCert
			}
			donorCertMu.Unlock()
		}

		go func(targetSNI string) {
			for attempt := 1; attempt <= 10; attempt++ {
				chain := fetchDonorCertificateChain(targetSNI)
				if len(chain) > 0 {
					donorCertMu.Lock()
					donorCertChains[targetSNI] = chain
					delete(clonedQuicCerts, targetSNI) // flush cached clone to upgrade
					if targetSNI == cfg.GetSNI() || serverCertDER == nil {
						serverCertDER = chain[0]
						donorCertChain = chain
					}
					donorCertMu.Unlock()
					log.Printf("[REALITY] Successfully upgraded to %d genuine donor certificates for %s", len(chain), targetSNI)
					return
				}
				time.Sleep(5 * time.Second)
			}
			log.Printf("[REALITY] Donor fetch exhausted; continuing with fallback certificate for %s", targetSNI)
		}(sni)
	})
}

func generateValidASN1Cert(sni string) []byte {
	ensureRSAKey()
	priv := serverRSAPrivKey
	if priv == nil {
		var err error
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil
		}
		serverRSAPrivKey = priv
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		serialNumber = big.NewInt(time.Now().UnixNano())
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{sni},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil
	}
	return der
}

func getDonorCertificateChain(sni string) [][]byte {
	if sni == "" {
		sni = "www.microsoft.com"
	}
	initServerKeys(sni)
	donorCertMu.RLock()
	chain := donorCertChains[sni]
	donorCertMu.RUnlock()
	if len(chain) > 0 {
		return chain
	}
	if der := generateValidASN1Cert(sni); len(der) > 0 {
		return [][]byte{der}
	}
	return nil
}

func generateClonedDonorChain(sni string) [][]byte {
	if sni == "" {
		sni = "speed.cloudflare.com"
	}
	initServerKeys(sni)
	donorCertMu.RLock()
	chain := donorCertChains[sni]
	donorCertMu.RUnlock()

	if len(chain) > 0 && serverRSAPrivKey != nil {
		if leaf, err := x509.ParseCertificate(chain[0]); err == nil {
			var customExts []pkix.Extension
			for _, ext := range leaf.Extensions {
				// Copy SCT list (Certificate Transparency) and custom extensions to preserve byte-for-byte size
				if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
					customExts = append(customExts, ext)
				}
			}

			template := x509.Certificate{
				SerialNumber:          leaf.SerialNumber,
				Subject:               leaf.Subject,
				Issuer:                leaf.Issuer,
				NotBefore:             leaf.NotBefore,
				NotAfter:              leaf.NotAfter,
				KeyUsage:              leaf.KeyUsage,
				ExtKeyUsage:           leaf.ExtKeyUsage,
				DNSNames:              leaf.DNSNames,
				IPAddresses:           leaf.IPAddresses,
				BasicConstraintsValid: leaf.BasicConstraintsValid,
				IsCA:                  leaf.IsCA,
				ExtraExtensions:       customExts,
			}
			if clonedDER, cErr := x509.CreateCertificate(rand.Reader, &template, &template, &serverRSAPrivKey.PublicKey, serverRSAPrivKey); cErr == nil {
				res := [][]byte{clonedDER}
				if len(chain) > 1 {
					res = append(res, chain[1:]...)
				}
				return res
			}
		}
	}

	fallback := generateValidASN1Cert(sni)
	if fallback != nil {
		return [][]byte{fallback}
	}
	return nil
}

func getQUICTLS13Cert(sni string) tls.Certificate {
	if sni == "" {
		sni = "speed.cloudflare.com"
	}
	initServerKeys(sni)

	donorCertMu.RLock()
	if cached, ok := clonedQuicCerts[sni]; ok && cached != nil {
		donorCertMu.RUnlock()
		return *cached
	}
	donorCertMu.RUnlock()

	chain := generateClonedDonorChain(sni)
	cert := tls.Certificate{
		Certificate: chain,
		PrivateKey:  serverRSAPrivKey,
	}

	donorCertMu.Lock()
	clonedQuicCerts[sni] = &cert
	donorCertMu.Unlock()
	return cert
}

// createTLS13AEAD selects the AEAD for the negotiated TLS 1.3 suite:
// 0x1301 -> AES-128-GCM (16-byte key)
// 0x1302 -> AES-256-GCM (32-byte key)
// 0x1303 -> ChaCha20-Poly1305 (32-byte key)
func createTLS13AEAD(cipherSuite uint16, key []byte) (cipher.AEAD, error) {
	switch cipherSuite {
	case 0x1301, 0x1302:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case 0x1303:
		return chacha20poly1305.New(key)
	default:
		return chacha20poly1305.New(key)
	}
}

// deriveTLS13HandshakeKeys derives Handshake Traffic Keys and Finished Keys
// per RFC 8446 specifications from TH1 = Hash(ClientHello || ServerHello).
func deriveTLS13HandshakeKeys(sharedSecret, staticSharedSecret, th1 []byte, cipherSuite uint16) (
	clientHandshakeKey, clientHandshakeIV,
	serverHandshakeKey, serverHandshakeIV,
	cFinKey, sFinKey []byte,
	masterSecret, masterSecretLegacy []byte,
) {
	// Combine ephemeral + static ECDH secrets
	ikm := sharedSecret
	if len(staticSharedSecret) > 0 {
		ikm = make([]byte, len(sharedSecret)+len(staticSharedSecret))
		copy(ikm, sharedSecret)
		copy(ikm[len(sharedSecret):], staticSharedSecret)
	}

	zeros := make([]byte, 32)
	emptyHash := sha256.Sum256(nil)
	// Early Secret = HKDF-Extract(salt=0, IKM=0)
	earlySecret := hkdf.Extract(sha256.New, zeros, nil)
	derivedEarly := hkdfExpandLabel(earlySecret, "derived", emptyHash[:], 32)

	// Handshake Secret = HKDF-Extract(salt=derivedEarly, IKM=ikm)
	handshakeSecret := hkdf.Extract(sha256.New, ikm, derivedEarly)

	cHsSecret := hkdfExpandLabel(handshakeSecret, "c hs traffic", th1, 32)
	sHsSecret := hkdfExpandLabel(handshakeSecret, "s hs traffic", th1, 32)

	keyLen := 32
	if cipherSuite == 0x1301 {
		keyLen = 16
	}

	clientHandshakeKey = hkdfExpandLabel(cHsSecret, "key", nil, keyLen)
	serverHandshakeKey = hkdfExpandLabel(sHsSecret, "key", nil, keyLen)
	clientHandshakeIV = hkdfExpandLabel(cHsSecret, "iv", nil, 12)
	serverHandshakeIV = hkdfExpandLabel(sHsSecret, "iv", nil, 12)

	cFinKey = hkdfExpandLabel(cHsSecret, "finished", nil, 32)
	sFinKey = hkdfExpandLabel(sHsSecret, "finished", nil, 32)

	// Master Secret = HKDF-Extract(salt=derivedHS, IKM=0)
	derivedHS := hkdfExpandLabel(handshakeSecret, "derived", emptyHash[:], 32)
	masterSecret = hkdf.Extract(sha256.New, zeros, derivedHS)
	masterSecretLegacy = hkdf.Extract(sha256.New, derivedHS, zeros)
	return
}

// deriveTLS13AppKeys derives Application Traffic Keys per RFC 8446
// from cumulative transcript hash TH3 = Hash(ClientHello...ServerFinished)
func deriveTLS13AppKeys(masterSecret []byte, th3 []byte, cipherSuite uint16) (
	clientAppKey, clientAppIV,
	serverAppKey, serverAppIV []byte,
) {
	cAppSecret := hkdfExpandLabel(masterSecret, "c ap traffic", th3, 32)
	sAppSecret := hkdfExpandLabel(masterSecret, "s ap traffic", th3, 32)

	keyLen := 32
	if cipherSuite == 0x1301 {
		keyLen = 16
	}

	clientAppKey = hkdfExpandLabel(cAppSecret, "key", nil, keyLen)
	serverAppKey = hkdfExpandLabel(sAppSecret, "key", nil, keyLen)
	clientAppIV = hkdfExpandLabel(cAppSecret, "iv", nil, 12)
	serverAppIV = hkdfExpandLabel(sAppSecret, "iv", nil, 12)
	return
}

func makeTLS13Nonce(baseIV [12]byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, baseIV[:])
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}
