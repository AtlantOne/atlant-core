package quicreality

import (
	"atlant.local/protocol/realityauth"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func testHello(pub []byte) []byte {
	// Complete minimal QUIC ClientHello with one X25519 key share.
	hello := append([]byte{1, 0, 0, 0, 3, 3}, make([]byte, 32)...)
	hello = append(hello, 0, 0, 2, 0x13, 1, 1, 0, 0, 42, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32)
	hello = append(hello, pub...)
	hello[3] = byte(len(hello) - 4)
	return hello
}

func TestDirectHelloBindsFullTranscriptAndPinnedServer(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{9}, 32)
	now := time.Now()
	hello := testHello(client.PublicKey().Bytes())
	a, err := BindHello(hello, "alice", key, client, server.PublicKey().Bytes(), now)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func([4]byte) []realityauth.Candidate { return []realityauth.Candidate{{Name: "alice", Key: key}} }
	b, err := VerifyHello(hello, server, lookup, now)
	if err != nil || a != b {
		t.Fatal("peer state mismatch", err)
	}
	for i := range hello {
		changed := bytes.Clone(hello)
		changed[i] ^= 1
		if _, err := VerifyHello(changed, server, lookup, now); err == nil {
			t.Fatalf("modified byte %d admitted", i)
		}
	}
	if _, err := VerifyHello(hello, server, lookup, now.Add(181*time.Second)); err == nil {
		t.Fatal("expired Hello")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := VerifyHello(hello, other, lookup, now); err == nil {
		t.Fatal("wrong pinned key")
	}
	cert, err := Certificate("localhost", a)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyCertificate(cert.Certificate, "localhost", b) != nil {
		t.Fatal("valid certificate proof")
	}
	b.PeerKey[0] ^= 1
	if VerifyCertificate(cert.Certificate, "localhost", b) == nil {
		t.Fatal("wrong server identity accepted")
	}
	if VerifyCertificate(cert.Certificate, "else.invalid", a) == nil {
		t.Fatal("wrong hostname accepted")
	}
}

func FuzzDirectHello(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0})
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	f.Fuzz(func(t *testing.T, hello []byte) {
		_, _ = VerifyHello(hello, server, func([4]byte) []realityauth.Candidate { return nil }, time.Now())
	})
}
