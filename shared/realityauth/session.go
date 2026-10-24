// Package realityauth implements the opt-in Atlant 3.x SessionID admission.
// It uses the existing pinned static X25519 server identity and 128-bit PSK
// proof. No CA, certificate issuance, HTTP endpoint or shared masking key.
package realityauth

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"
)

var ErrAuthentication = errors.New("REALITY admission authentication failed")

type Candidate struct {
	Name string
	Key  []byte
}

func mask(shared, nonce []byte) []byte {
	m := hmac.New(sha256.New, shared)
	m.Write([]byte("atlant/reality/session/3/mask\x00"))
	m.Write(nonce)
	return m.Sum(nil)
}

func proof(user string, key, raw, clientPub, serverPub []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("atlant/reality/session/3/proof\x00"))
	m.Write([]byte{byte(len(user))})
	m.Write([]byte(user))
	m.Write(raw)
	m.Write(clientPub)
	m.Write(serverPub)
	return m.Sum(nil)[:16]
}

// Generate requires a freshly generated client ephemeral key for EACH handshake.
// Bytes 0..7 mask tag and timestamp; 8..15 are CSPRNG nonce; 16..31 are
// domain-separated HMAC-128 over identity, clear payload and both public keys.
func Generate(user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time) ([32]byte, error) {
	return generate(user, key, client, serverPub, now, rand.Reader)
}

func generate(user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time, random io.Reader) ([32]byte, error) {
	var token [32]byte
	if len(user) < 1 || len(user) > 64 || len(key) != 32 || client == nil || now.Unix() < 0 || now.Unix() > int64(^uint32(0)) {
		return token, ErrAuthentication
	}
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return token, ErrAuthentication
	}
	shared, err := client.ECDH(pub)
	if err != nil {
		return token, ErrAuthentication
	}
	defer clear(shared)
	var raw [16]byte
	tag := sha256.Sum256([]byte(user))
	copy(raw[:4], tag[:4])
	binary.BigEndian.PutUint32(raw[4:8], uint32(now.Unix()))
	if _, err := io.ReadFull(random, raw[8:]); err != nil {
		return token, err
	}
	m := mask(shared, raw[8:])
	for i := 0; i < 8; i++ {
		token[i] = raw[i] ^ m[i]
	}
	copy(token[8:16], raw[8:])
	copy(token[16:], proof(user, key, raw[:], client.PublicKey().Bytes(), serverPub))
	return token, nil
}

// Verify performs one X25519 operation and a bounded tag-index lookup, not
// an O(N) PBK search. Caller must enforce replay retention AFTER success and
// retain mutual TLS-Finished/QUIC exporter authentication before proxy traffic.
func Verify(token, clientPub []byte, server *ecdh.PrivateKey, lookup func([4]byte) []Candidate, now time.Time) (Candidate, error) {
	if len(token) != 32 || server == nil || lookup == nil {
		return Candidate{}, ErrAuthentication
	}
	pub, err := ecdh.X25519().NewPublicKey(clientPub)
	if err != nil {
		return Candidate{}, ErrAuthentication
	}
	shared, err := server.ECDH(pub)
	if err != nil {
		return Candidate{}, ErrAuthentication
	}
	defer clear(shared)
	var raw [16]byte
	m := mask(shared, token[8:16])
	for i := 0; i < 8; i++ {
		raw[i] = token[i] ^ m[i]
	}
	copy(raw[8:], token[8:16])
	delta := now.Unix() - int64(binary.BigEndian.Uint32(raw[4:8]))
	if delta < -180 || delta > 180 {
		return Candidate{}, ErrAuthentication
	}
	var tag [4]byte
	copy(tag[:], raw[:4])
	candidates := lookup(tag)
	// Fail closed under a pathological hash-collision bucket.
	if len(candidates) > 16 {
		return Candidate{}, ErrAuthentication
	}
	for _, candidate := range candidates {
		if len(candidate.Name) < 1 || len(candidate.Name) > 64 || len(candidate.Key) != 32 {
			continue
		}
		expectedTag := sha256.Sum256([]byte(candidate.Name))
		if !hmac.Equal(raw[:4], expectedTag[:4]) {
			continue
		}
		if hmac.Equal(token[16:], proof(candidate.Name, candidate.Key, raw[:], clientPub, server.PublicKey().Bytes())) {
			return candidate, nil
		}
	}
	return Candidate{}, ErrAuthentication
}
