package quicpeer

import (
	"bytes"
	"testing"
	"time"
)

func TestConnectionIDsAreUniqueAndVerifiable(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	generator := NewCIDGenerator("alice", key)
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		cid, err := generator.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		data := cid.Bytes()
		before := append([]byte(nil), data...)
		if seen[string(data)] {
			t.Fatal("repeated QUIC Connection ID")
		}
		seen[string(data)] = true
		if _, ok := CIDUserTag(data); !ok || !VerifyCID(data, key, time.Now()) {
			t.Fatal("generated CID failed verification")
		}
		if !bytes.Equal(data, before) {
			t.Fatal("CID verification mutated the received packet")
		}
		if VerifyCID(data, key, time.Now().Add(4*time.Minute)) {
			t.Fatal("expired CID accepted")
		}
		data[19] ^= 1
		if VerifyCID(data, key, time.Now()) {
			t.Fatal("forged CID accepted")
		}
	}
}
