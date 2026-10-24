package realityauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func TestFullHelloAdmissionRejectsModifiedPublicFields(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{7}, 32)
	lookup := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }
	hello := make([]byte, 128)
	hello[0], hello[3], hello[38] = 1, 124, 32
	record := append([]byte{22, 3, 1, 0, 128}, hello...)
	if err := BindHelloRecord(record, "alice", key, client, server.PublicKey().Bytes(), time.Now()); err != nil {
		t.Fatal(err)
	}
	hello = record[5:]
	if _, err := VerifyHello(hello[39:71], client.PublicKey().Bytes(), hello, server, lookup, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{4, 6, 37, 71, 100, 127} {
		changed := bytes.Clone(hello)
		changed[offset] ^= 1
		if _, err := VerifyHello(changed[39:71], client.PublicKey().Bytes(), changed, server, lookup, time.Now()); err == nil {
			t.Fatalf("modified byte %d accepted", offset)
		}
	}
	for _, version := range []int{3, 4} {
		if _, err := VerifyVersion(version, hello[39:71], client.PublicKey().Bytes(), server, func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }, time.Now()); err == nil {
			t.Fatal("cross-version admission accepted")
		}
	}
	bad := bytes.Clone(record)
	binary.BigEndian.PutUint16(bad[3:5], 127)
	if BindHelloRecord(bad, "alice", key, client, server.PublicKey().Bytes(), time.Now()) == nil {
		t.Fatal("truncated record accepted")
	}
}
