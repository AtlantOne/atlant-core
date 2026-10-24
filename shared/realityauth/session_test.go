package realityauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func TestSessionBindingTamperExpiryAndNoPublicLegacyTag(t *testing.T) {
	s, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c, _ := ecdh.X25519().GenerateKey(rand.Reader)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{5}, 32)
	now := time.Unix(1800000000, 0)
	lookup := func(tag [4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }
	token, err := Generate("alice", key, c, s.PublicKey().Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Verify(token[:], c.PublicKey().Bytes(), s, lookup, now); err != nil || got.Name != "alice" {
		t.Fatal(err)
	}
	for i := range token {
		broken := token
		broken[i] ^= 1
		if _, err := Verify(broken[:], c.PublicKey().Bytes(), s, lookup, now); err == nil {
			t.Fatal("tamper accepted", i)
		}
	}
	if _, err := Verify(token[:], other.PublicKey().Bytes(), s, lookup, now); err == nil {
		t.Fatal("different key_share accepted")
	}
	if _, err := Verify(token[:], c.PublicKey().Bytes(), other, lookup, now); err == nil {
		t.Fatal("different pinned server accepted")
	}
	for _, d := range []time.Duration{-181 * time.Second, 181 * time.Second} {
		if _, err := Verify(token[:], c.PublicKey().Bytes(), s, lookup, now.Add(d)); err == nil {
			t.Fatal("expiry accepted")
		}
	}
	wrong := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: bytes.Repeat([]byte{7}, 32)}} }
	if _, err := Verify(token[:], c.PublicKey().Bytes(), s, wrong, now); err == nil {
		t.Fatal("wrong PSK accepted")
	}
	// Even with only one identity in this fixture the legacy public decoder
	// must not recover its tag across independently generated key shares.
	want := sha256.Sum256([]byte("alice"))
	for i := 0; i < 100; i++ {
		eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
		v, err := Generate("alice", key, eph, s.PublicKey().Bytes(), now)
		if err != nil {
			t.Fatal(err)
		}
		pub := eph.PublicKey().Bytes()
		nm := sha256.Sum256(append([]byte("atlant-nonce-v3"), pub...))
		nonce := append([]byte(nil), v[4:16]...)
		for j := 0; j < 4; j++ {
			nonce[j] ^= nm[j]
		}
		m := sha256.Sum256(append(nonce, pub...))
		var recovered [4]byte
		for j := 0; j < 4; j++ {
			recovered[j] = v[j] ^ m[j]
		}
		if bytes.Equal(recovered[:], want[:4]) {
			t.Fatal("legacy public tag recovered")
		}
	}
}

func TestEntropyInvalidKeyAndCollisionBucketFailClosed(t *testing.T) {
	s, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := make([]byte, 32)
	now := time.Now()
	if _, err := generate("alice", key, c, s.PublicKey().Bytes(), now, bytes.NewReader(nil)); err == nil {
		t.Fatal("entropy fallback")
	}
	if _, err := Generate("alice", key, c, make([]byte, 32), now); err == nil {
		t.Fatal("low order key")
	}
	token, _ := Generate("alice", key, c, s.PublicKey().Bytes(), now)
	if _, err := Verify(token[:], c.PublicKey().Bytes(), s, func([4]byte) []Candidate { return make([]Candidate, 17) }, now); err == nil {
		t.Fatal("unbounded collision search")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add(make([]byte, 32), make([]byte, 32))
	s, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f.Fuzz(func(t *testing.T, token, pub []byte) {
		_, _ = Verify(token, pub, s, func([4]byte) []Candidate { return nil }, time.Now())
	})
}
