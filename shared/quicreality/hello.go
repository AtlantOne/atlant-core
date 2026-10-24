// Package quicreality implements Atlant's experimental direct-UDP wire7 admission.
// It is not the Xray REALITY protocol and has not had an independent crypto audit.
package quicreality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"atlant.local/protocol/realityauth"
)

var ErrAuthentication = errors.New("direct QUIC REALITY authentication failed")

const MaxHello = 8192

type Admission struct {
	User      string
	HelloHash [32]byte
	PeerKey   [32]byte
	Expires   int64
}

// ParseHello requires a complete QUIC TLS ClientHello with empty SessionID.
func ParseHello(hello []byte) (digest [32]byte, share []byte, err error) {
	if len(hello) < 42 || len(hello) > MaxHello || hello[0] != 1 || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 || hello[38] != 0 {
		return digest, nil, ErrAuthentication
	}
	copyHello := bytes.Clone(hello)
	clear(copyHello[6:38])
	digest = sha256.Sum256(copyHello)
	p := hello[39:]
	for _, prefix := range []int{2, 1} {
		if len(p) < prefix {
			return digest, nil, ErrAuthentication
		}
		n := int(p[0])
		if prefix == 2 {
			n = int(binary.BigEndian.Uint16(p))
		}
		if n > len(p)-prefix {
			return digest, nil, ErrAuthentication
		}
		p = p[prefix+n:]
	}
	if len(p) < 2 || int(binary.BigEndian.Uint16(p)) != len(p)-2 {
		return digest, nil, ErrAuthentication
	}
	p = p[2:]
	for len(p) > 0 {
		if len(p) < 4 {
			return digest, nil, ErrAuthentication
		}
		typ, n := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if n > len(p) {
			return digest, nil, ErrAuthentication
		}
		if typ == 51 {
			q := p[:n]
			if len(q) < 2 || int(binary.BigEndian.Uint16(q)) != len(q)-2 {
				return digest, nil, ErrAuthentication
			}
			q = q[2:]
			for len(q) > 0 {
				if len(q) < 4 {
					return digest, nil, ErrAuthentication
				}
				group, m := binary.BigEndian.Uint16(q), int(binary.BigEndian.Uint16(q[2:]))
				q = q[4:]
				if m > len(q) {
					return digest, nil, ErrAuthentication
				}
				if group == 29 && m == 32 {
					if share != nil {
						return digest, nil, ErrAuthentication
					}
					share = bytes.Clone(q[:m])
				}
				q = q[m:]
			}
		}
		p = p[n:]
	}
	if share == nil {
		return digest, nil, ErrAuthentication
	}
	return digest, share, nil
}

func mac(key []byte, domain string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("atlant/quic-reality/wire7/" + domain + "\x00"))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func helloProof(key, shared []byte, digest [32]byte, raw []byte, user string) []byte {
	return mac(key, "client-hello", shared, digest[:], raw, []byte{byte(len(user))}, []byte(user))[:16]
}

func peerKey(key, shared, hello []byte) [32]byte {
	h := sha256.Sum256(hello)
	var out [32]byte
	copy(out[:], mac(key, "server-identity", shared, h[:]))
	return out
}

// BindHello is called before TLS transcript hashing. No packet-layer rewriting.
func BindHello(hello []byte, user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time) (Admission, error) {
	digest, share, err := ParseHello(hello)
	if err != nil || client == nil || len(key) != 32 || len(user) < 1 || len(user) > 64 || !bytes.Equal(share, client.PublicKey().Bytes()) || now.Unix() < 0 || now.Unix() > int64(^uint32(0)) {
		return Admission{}, ErrAuthentication
	}
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return Admission{}, ErrAuthentication
	}
	shared, err := client.ECDH(pub)
	if err != nil {
		return Admission{}, ErrAuthentication
	}
	defer clear(shared)
	var raw [16]byte
	tag := sha256.Sum256([]byte(user))
	copy(raw[:4], tag[:4])
	binary.BigEndian.PutUint32(raw[4:8], uint32(now.Unix()))
	if _, err := rand.Read(raw[8:]); err != nil {
		return Admission{}, err
	}
	mask := mac(shared, "identity-mask", digest[:], raw[8:])
	for i := 0; i < 8; i++ {
		hello[6+i] = raw[i] ^ mask[i]
	}
	copy(hello[14:22], raw[8:])
	copy(hello[22:38], helloProof(key, shared, digest, raw[:], user))
	return Admission{User: user, HelloHash: sha256.Sum256(hello), PeerKey: peerKey(key, shared, hello), Expires: now.Unix() + 180}, nil
}

// VerifyHello has no one-shot side effect: copying a Hello cannot consume its
// owner's admission. Only successful TLS plus mutual exporter proof may commit.
// Static-key compromise can recover historical tag/time: accepted wire7 tradeoff.
func VerifyHello(hello []byte, server *ecdh.PrivateKey, lookup func([4]byte) []realityauth.Candidate, now time.Time) (Admission, error) {
	digest, share, err := ParseHello(hello)
	if err != nil || server == nil || lookup == nil {
		return Admission{}, ErrAuthentication
	}
	pub, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return Admission{}, ErrAuthentication
	}
	shared, err := server.ECDH(pub)
	if err != nil {
		return Admission{}, ErrAuthentication
	}
	defer clear(shared)
	var raw [16]byte
	mask := mac(shared, "identity-mask", digest[:], hello[14:22])
	for i := 0; i < 8; i++ {
		raw[i] = hello[6+i] ^ mask[i]
	}
	copy(raw[8:], hello[14:22])
	stamp := int64(binary.BigEndian.Uint32(raw[4:8]))
	delta := now.Unix() - stamp
	if delta < -180 || delta > 180 {
		return Admission{}, ErrAuthentication
	}
	var tag [4]byte
	copy(tag[:], raw[:4])
	candidates := lookup(tag)
	if len(candidates) > 16 {
		return Admission{}, ErrAuthentication
	}
	for _, c := range candidates {
		if len(c.Key) != 32 || len(c.Name) < 1 || len(c.Name) > 64 {
			continue
		}
		expectedTag := sha256.Sum256([]byte(c.Name))
		if !hmac.Equal(tag[:], expectedTag[:4]) {
			continue
		}
		if hmac.Equal(hello[22:38], helloProof(c.Key, shared, digest, raw[:], c.Name)) {
			return Admission{User: c.Name, HelloHash: sha256.Sum256(hello), PeerKey: peerKey(c.Key, shared, hello), Expires: stamp + 180}, nil
		}
	}
	return Admission{}, ErrAuthentication
}
