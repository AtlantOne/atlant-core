package main

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Passing documents a known LEGACY weakness. This is not a claim that the
// construction resists passive linking. No secret is supplied to the decoder.
func TestLegacySessionIDPublicTagRecoveryAudit(t *testing.T) {
	wanted := sha256.Sum256([]byte("audit_alice"))
	for i := byte(1); i < 9; i++ {
		publicKey := bytes.Repeat([]byte{i}, 32)
		token, _ := generateSessionIDTokenBound("audit_alice", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", publicKey)
		nonceMask := sha256.Sum256(append([]byte("atlant-nonce-v3"), publicKey...))
		nonce := append([]byte(nil), token[4:16]...)
		for j := 0; j < 4; j++ {
			nonce[j] ^= nonceMask[j]
		}
		mask := sha256.Sum256(append(nonce, publicKey...))
		var recovered [4]byte
		for j := 0; j < 4; j++ {
			recovered[j] = token[j] ^ mask[j]
		}
		if !bytes.Equal(recovered[:], wanted[:4]) {
			t.Fatal("legacy format changed: re-audit public identity fields")
		}
	}
}
