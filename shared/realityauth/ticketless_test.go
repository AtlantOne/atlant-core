package realityauth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestTicketlessHelloBindsEveryByte(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{7}, 32)
	now := time.Now()
	hello := make([]byte, 128)
	hello[0], hello[3], hello[38] = 1, 124, 32
	record := append([]byte{22, 3, 1, 0, 128}, hello...)
	if err := BindHelloRecord(record, "alice", key, client, server.PublicKey().Bytes(), now); err != nil {
		t.Fatal(err)
	}
	hello = record[5:]
	lookup := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: key}} }
	for i := 0; i < 2; i++ {
		got, err := VerifyHello(hello[39:71], client.PublicKey().Bytes(), hello, server, lookup, now)
		if err != nil || !bytes.Equal(got.Key, key) {
			t.Fatal("valid original key lost", err)
		}
	}
	for i := range hello {
		changed := bytes.Clone(hello)
		changed[i] ^= 1
		if _, err := VerifyHello(changed[39:71], client.PublicKey().Bytes(), changed, server, lookup, now); err == nil {
			t.Fatalf("changed byte %d admitted", i)
		}
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := VerifyHello(hello[39:71], other.PublicKey().Bytes(), hello, server, lookup, now); err == nil {
		t.Fatal("wrong client key admitted")
	}
	if _, err := VerifyHello(hello[39:71], client.PublicKey().Bytes(), hello, other, lookup, now); err == nil {
		t.Fatal("wrong server key admitted")
	}
	wrong := func([4]byte) []Candidate { return []Candidate{{Name: "alice", Key: bytes.Repeat([]byte{8}, 32)}} }
	if _, err := VerifyHello(hello[39:71], client.PublicKey().Bytes(), hello, server, wrong, now); err == nil {
		t.Fatal("wrong PSK admitted")
	}
	if _, err := VerifyHello(hello[39:71], client.PublicKey().Bytes(), hello, server, lookup, now.Add(181*time.Second)); err == nil {
		t.Fatal("expired admission accepted")
	}
	for _, version := range []int{3, 4} {
		if _, err := VerifyVersion(version, hello[39:71], client.PublicKey().Bytes(), server, lookup, now); err == nil {
			t.Fatalf("wire6 accepted as wire%d", version)
		}
		token, err := GenerateVersion(version, "alice", key, client, server.PublicKey().Bytes(), now)
		if err != nil {
			t.Fatal(err)
		}
		changed := bytes.Clone(hello)
		copy(changed[39:71], token[:])
		if _, err := VerifyHello(token[:], client.PublicKey().Bytes(), changed, server, lookup, now); err == nil {
			t.Fatalf("wire%d accepted as wire6", version)
		}
	}
}

func TestTicketlessMalformedRecordsFailClosed(t *testing.T) {
	for n := 0; n < 133; n++ {
		if err := BindHelloRecord(make([]byte, n), "alice", bytes.Repeat([]byte{1}, 32), nil, nil, time.Now()); err == nil {
			t.Fatalf("invalid record of size %d", n)
		}
	}
}

func FuzzTicketlessHello(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f.Fuzz(func(t *testing.T, hello []byte) {
		_, _ = VerifyHello(make([]byte, 32), make([]byte, 32), hello, server, func([4]byte) []Candidate { return nil }, time.Now())
	})
}
