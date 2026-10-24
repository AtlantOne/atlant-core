//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

func getUserTag(username string) [4]byte {
	h := sha256.Sum256([]byte(username))
	var tag [4]byte
	copy(tag[:], h[:4])
	return tag
}

var (
	udpBlockedMu sync.RWMutex
	udpBlocked   bool
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

func parsePBKBytes(pbk string) []byte {
	trimmed := strings.TrimSpace(pbk)
	b, err := hex.DecodeString(trimmed)
	if err == nil && len(b) == 32 {
		return b
	}
	h := sha256.Sum256([]byte(trimmed))
	return h[:]
}

// HKDF-Expand-Label per RFC 8446 (TLS 1.3 Key Schedule)
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	return hkdfExpandLabelHash(sha256.New, secret, label, context, length)
}

func hkdfExpandLabelHash(h func() hash.Hash, secret []byte, label string, context []byte, length int) []byte {
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
	kdf := hkdf.Expand(h, secret, labelBytes)
	if _, err := io.ReadFull(kdf, out); err != nil {
		log.Printf("[CRYPTO] hkdfExpandLabel error: %v", err)
	}
	return out
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
		return nil, fmt.Errorf("unsupported TLS 1.3 cipher suite: 0x%04x", cipherSuite)
	}
}

func deriveTLS13HandshakeKeys(sharedSecret, staticSharedSecret, th1 []byte, cipherSuite uint16) (
	clientHandshakeKey, clientHandshakeIV,
	serverHandshakeKey, serverHandshakeIV,
	cFinKey, sFinKey []byte,
	masterSecret []byte,
) {
	hashFunc := sha256.New
	hashLen := 32
	if cipherSuite == 0x1302 {
		hashFunc = sha512.New384
		hashLen = 48
	}

	// Combine ephemeral + static ECDH secrets (2-ECDH Reality)
	ikm := sharedSecret
	if len(staticSharedSecret) > 0 {
		ikm = make([]byte, len(sharedSecret)+len(staticSharedSecret))
		copy(ikm, sharedSecret)
		copy(ikm[len(sharedSecret):], staticSharedSecret)
	}

	zeros := make([]byte, hashLen)
	h := hashFunc()
	emptyHash := h.Sum(nil)

	// Early Secret = HKDF-Extract(salt=0, IKM=0)
	earlySecret := hkdf.Extract(hashFunc, zeros, nil)
	derivedEarly := hkdfExpandLabelHash(hashFunc, earlySecret, "derived", emptyHash, hashLen)

	// Handshake Secret = HKDF-Extract(salt=derivedEarly, IKM=ikm)
	handshakeSecret := hkdf.Extract(hashFunc, ikm, derivedEarly)

	cHsSecret := hkdfExpandLabelHash(hashFunc, handshakeSecret, "c hs traffic", th1, hashLen)
	sHsSecret := hkdfExpandLabelHash(hashFunc, handshakeSecret, "s hs traffic", th1, hashLen)

	keyLen := 32
	if cipherSuite == 0x1301 {
		keyLen = 16
	}

	clientHandshakeKey = hkdfExpandLabelHash(hashFunc, cHsSecret, "key", nil, keyLen)
	serverHandshakeKey = hkdfExpandLabelHash(hashFunc, sHsSecret, "key", nil, keyLen)
	clientHandshakeIV = hkdfExpandLabelHash(hashFunc, cHsSecret, "iv", nil, 12)
	serverHandshakeIV = hkdfExpandLabelHash(hashFunc, sHsSecret, "iv", nil, 12)

	cFinKey = hkdfExpandLabelHash(hashFunc, cHsSecret, "finished", nil, hashLen)
	sFinKey = hkdfExpandLabelHash(hashFunc, sHsSecret, "finished", nil, hashLen)

	// Master Secret = HKDF-Extract(salt=derivedHS, IKM=0)
	derivedHS := hkdfExpandLabelHash(hashFunc, handshakeSecret, "derived", emptyHash, hashLen)
	masterSecret = hkdf.Extract(hashFunc, zeros, derivedHS)
	return
}

func deriveTLS13AppKeys(masterSecret []byte, th3 []byte, cipherSuite uint16) (
	clientAppKey, clientAppIV,
	serverAppKey, serverAppIV []byte,
) {
	hashFunc := sha256.New
	hashLen := 32
	if cipherSuite == 0x1302 {
		hashFunc = sha512.New384
		hashLen = 48
	}

	cAppSecret := hkdfExpandLabelHash(hashFunc, masterSecret, "c ap traffic", th3, hashLen)
	sAppSecret := hkdfExpandLabelHash(hashFunc, masterSecret, "s ap traffic", th3, hashLen)

	keyLen := 32
	if cipherSuite == 0x1301 {
		keyLen = 16
	}

	clientAppKey = hkdfExpandLabelHash(hashFunc, cAppSecret, "key", nil, keyLen)
	serverAppKey = hkdfExpandLabelHash(hashFunc, sAppSecret, "key", nil, keyLen)
	clientAppIV = hkdfExpandLabelHash(hashFunc, cAppSecret, "iv", nil, 12)
	serverAppIV = hkdfExpandLabelHash(hashFunc, sAppSecret, "iv", nil, 12)
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

type realitySecureConn struct {
	readHeader  [5]byte
	readNonce   [12]byte
	recordBuf   tlsRecordBuffer
	xhttpBatch  bool
	writeErr    error
	writeClosed bool
	net.Conn
	encAead cipher.AEAD
	decAead cipher.AEAD
	encIV   [12]byte
	decIV   [12]byte
	encSeq  uint64
	decSeq  uint64
	readBuf []byte
	decBuf  []byte
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func generateSessionIDTokenBound(username, pbk string, clientPubKey []byte) ([32]byte, []byte) {
	var token [32]byte
	h := sha256.Sum256([]byte(username))
	var userTag [4]byte
	copy(userTag[:], h[:4])

	var rawNonce [12]byte
	binary.BigEndian.PutUint32(rawNonce[:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(rawNonce[4:]); err != nil {
		binary.BigEndian.PutUint64(rawNonce[4:12], uint64(time.Now().UnixNano()))
	}

	// Legacy masking is publicly reversible; it does not hide the timestamp.
	nonceMask := sha256.Sum256(append([]byte("atlant-nonce-v3"), clientPubKey...))
	for i := 0; i < 4; i++ {
		token[4+i] = rawNonce[i] ^ nonceMask[i]
	}
	copy(token[8:16], rawNonce[4:12])

	// Keep the wire2 codec for compatibility. Wire3 uses secret ECDH masking.
	maskHash := sha256.Sum256(append(rawNonce[:], clientPubKey...))
	for i := 0; i < 4; i++ {
		token[i] = userTag[i] ^ maskHash[i]
	}

	pbkBytes := parsePBKBytes(pbk)
	mac := hmac.New(sha256.New, pbkBytes)
	mac.Write(rawNonce[:])
	if len(clientPubKey) == 32 {
		mac.Write(clientPubKey)
	}
	copy(token[16:32], mac.Sum(nil)[:16]) // 16-byte HMAC

	nonceCopy := make([]byte, 12)
	copy(nonceCopy, rawNonce[:])
	return token, nonceCopy
}
