package realityauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestTCPWire6Wire7ProofsDoNotCross(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{9}, 32)
	lookup := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }
	for _, version := range []int{6, 7} {
		hello := make([]byte, 128)
		hello[0], hello[3], hello[38] = 1, 124, 32
		record := append([]byte{22, 3, 1, 0, 128}, hello...)
		if err := BindHelloVersion(version, record, "alice", key, client, server.PublicKey().Bytes(), time.Now()); err != nil {
			t.Fatal(err)
		}
		hello = record[5:]
		if _, err := VerifyHelloVersion(version, hello[39:71], client.PublicKey().Bytes(), hello, server, lookup, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyHelloVersion(13-version, hello[39:71], client.PublicKey().Bytes(), hello, server, lookup, time.Now()); err == nil {
			t.Fatal("cross-version admission")
		}
	}
}
