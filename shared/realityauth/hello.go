package realityauth

import (
	"crypto/sha256"
)

// HelloDigest covers the exact TLS handshake message, not TLS record framing.
// Only the 32-byte SessionID is zeroed to break the authentication self-reference.
// SessionID metadata and proof are independently authenticated by VerifyHello.
func HelloDigest(hello []byte) ([32]byte, error) {
	if len(hello) < 71 || len(hello) > 65536 || hello[0] != 1 ||
		(int(hello[1])<<16|int(hello[2])<<8|int(hello[3])) != len(hello)-4 || hello[38] != 32 {
		return [32]byte{}, ErrAuthentication
	}
	h := sha256.New()
	h.Write(hello[:39])
	var zero [32]byte
	h.Write(zero[:])
	h.Write(hello[71:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
