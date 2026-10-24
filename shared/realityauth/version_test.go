package realityauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestWire4ProofDoesNotDowngradeToWire3(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{7}, 32)
	lookup := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }
	for _, version := range []int{3, 4} {
		token, err := GenerateVersion(version, "alice", key, client, server.PublicKey().Bytes(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		got, err := VerifyVersion(version, token[:], client.PublicKey().Bytes(), server, lookup, time.Now())
		if err != nil || !bytes.Equal(got.Key, key) {
			t.Fatal("original traffic key not preserved", err)
		}
		if _, err := VerifyVersion(7-version, token[:], client.PublicKey().Bytes(), server, lookup, time.Now()); err == nil {
			t.Fatal("cross-version proof accepted")
		}
	}
}
