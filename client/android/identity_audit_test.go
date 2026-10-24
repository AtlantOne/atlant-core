//go:build android || (linux && atlanttest)

package atlant

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// Documents an EXISTING legacy limitation, not a successful privacy defense.
// The decoder receives only public SessionID/key_share bytes, never the PBK.
// Keep this test for 2.x even after a separate new profile is introduced.
func TestLegacySessionIDPublicTagRecoveryAudit(t *testing.T) {
	user := "audit_alice"
	wanted := sha256.Sum256([]byte(user))
	for i := byte(1); i < 9; i++ {
		publicKey := bytes.Repeat([]byte{i}, 32)
		token, _ := generateSessionIDTokenBound(user, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", publicKey)
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
			t.Fatal("legacy format changed: review public-field privacy assumptions")
		}
		timestamp := int64(binary.BigEndian.Uint32(nonce[:4]))
		if delta := time.Now().Unix() - timestamp; delta < 0 || delta > 5 {
			t.Fatal("legacy timestamp recovery changed")
		}
	}
	t.Log("Confirmed known legacy public tag/timestamp recovery; NOT a privacy test pass for a new format")
}
