package realityauth

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"time"
)

// Wire4 retains wire3's metadata mask, but domain-separates the admission
// proof. A wire3 handshake cannot silently enable wire4 packet registration.
func wire4Key(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("atlant/reality/wire4/admission-key\x00"))
	return m.Sum(nil)
}

func GenerateVersion(version int, user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time) ([32]byte, error) {
	if version == 3 {
		return Generate(user, key, client, serverPub, now)
	}
	if version != 4 || len(key) != 32 {
		return [32]byte{}, ErrAuthentication
	}
	derived := wire4Key(key)
	defer clear(derived)
	return Generate(user, derived, client, serverPub, now)
}

func VerifyVersion(version int, token, clientPub []byte, server *ecdh.PrivateKey, lookup func([4]byte) []Candidate, now time.Time) (Candidate, error) {
	if version == 3 {
		return Verify(token, clientPub, server, lookup, now)
	}
	if version != 4 || lookup == nil {
		return Candidate{}, ErrAuthentication
	}
	var originals []Candidate
	var derived []Candidate
	defer func() {
		for _, candidate := range derived {
			clear(candidate.Key)
		}
	}()
	candidate, err := Verify(token, clientPub, server, func(tag [4]byte) []Candidate {
		originals = lookup(tag)
		if len(originals) > 16 {
			return make([]Candidate, 17)
		}
		for _, original := range originals {
			if len(original.Key) == 32 {
				derived = append(derived, Candidate{Name: original.Name, Key: wire4Key(original.Key)})
			}
		}
		return derived
	}, now)
	if err != nil {
		return Candidate{}, err
	}
	for _, original := range originals {
		if original.Name == candidate.Name && len(original.Key) == 32 && hmac.Equal(wire4Key(original.Key), candidate.Key) {
			return original, nil
		}
	}
	return Candidate{}, ErrAuthentication
}
