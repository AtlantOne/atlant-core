package realityauth

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"time"
)

// Wire6 keeps indexed per-user admission without a ticket store. The key is
// bound to the entire ClientHello, excluding the self-referential SessionID.
// It intentionally does not provide forward secrecy for identity metadata.
func helloKey(version int, key []byte, digest [32]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("atlant/reality/wire" + strconv.Itoa(version) + "/full-hello/key\x00"))
	m.Write(digest[:])
	return m.Sum(nil)
}

func BindHelloRecord(record []byte, user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time) error {
	return BindHelloVersion(6, record, user, key, client, serverPub, now)
}

func BindHelloVersion(version int, record []byte, user string, key []byte, client *ecdh.PrivateKey, serverPub []byte, now time.Time) error {
	if version != 6 && version != 7 {
		return ErrAuthentication
	}
	if len(key) != 32 || len(record) < 5 || record[0] != 22 || (int(record[3])<<8|int(record[4])) != len(record)-5 {
		return ErrAuthentication
	}
	digest, err := HelloDigest(record[5:])
	if err != nil {
		return err
	}
	derived := helloKey(version, key, digest)
	defer clear(derived)
	token, err := Generate(user, derived, client, serverPub, now)
	if err != nil {
		return err
	}
	copy(record[44:76], token[:])
	return nil
}

// The caller commits replay state only after verifying client Finished.
func VerifyHello(token, clientPub, hello []byte, server *ecdh.PrivateKey, lookup func([4]byte) []Candidate, now time.Time) (Candidate, error) {
	return VerifyHelloVersion(6, token, clientPub, hello, server, lookup, now)
}

func VerifyHelloVersion(version int, token, clientPub, hello []byte, server *ecdh.PrivateKey, lookup func([4]byte) []Candidate, now time.Time) (Candidate, error) {
	if version != 6 && version != 7 {
		return Candidate{}, ErrAuthentication
	}
	digest, err := HelloDigest(hello)
	if err != nil || lookup == nil || len(token) != 32 || !hmac.Equal(token, hello[39:71]) {
		return Candidate{}, ErrAuthentication
	}
	var originals []Candidate
	var derived []Candidate
	defer func() {
		for _, c := range derived {
			clear(c.Key)
		}
	}()
	verified, err := Verify(token, clientPub, server, func(tag [4]byte) []Candidate {
		originals = lookup(tag)
		if len(originals) > 16 {
			return make([]Candidate, 17)
		}
		for _, c := range originals {
			if len(c.Key) == 32 {
				derived = append(derived, Candidate{Name: c.Name, Key: helloKey(version, c.Key, digest)})
			}
		}
		return derived
	}, now)
	if err != nil {
		return Candidate{}, err
	}
	for _, c := range originals {
		if c.Name == verified.Name && len(c.Key) == 32 {
			return c, nil
		}
	}
	return Candidate{}, ErrAuthentication
}
