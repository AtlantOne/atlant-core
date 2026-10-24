package wire

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"slices"
)

const TLSMaxRecordsPerKey uint64 = 1 << 24

func CheckTLSKeyUsage(sequence uint64) error {
	if sequence >= TLSMaxRecordsPerKey {
		return fmt.Errorf("TLS traffic key usage limit reached: reconnect required")
	}
	return nil
}

// TLSRecordBuffer reuses private per-connection storage. Callers retain their
// record boundaries and padding policy, including when batching socket writes.
// The returned slice is valid until the next Seal and must not be retained.
// Callers must serialize Seal and the following socket write.
type TLSRecordBuffer struct {
	buffer []byte
	nonce  [12]byte
}

// TLSNonce fills caller-owned storage; each I/O direction owns its own nonce.
func TLSNonce(dst *[12]byte, iv [12]byte, sequence uint64) []byte {
	*dst = iv
	binary.BigEndian.PutUint64(dst[4:], binary.BigEndian.Uint64(iv[4:])^sequence)
	return dst[:]
}

func (b *TLSRecordBuffer) Seal(aead cipher.AEAD, iv [12]byte, sequence uint64, payload []byte, contentType byte, padding int) ([]byte, error) {
	b.ResetBatch()
	return b.AppendSeal(aead, iv, sequence, payload, contentType, padding)
}

func (b *TLSRecordBuffer) ResetBatch() { b.buffer = b.buffer[:0] }

// AppendSeal appends a complete record without changing preceding records.
// The caller must flush/reset within four records to keep storage bounded.
func (b *TLSRecordBuffer) AppendSeal(aead cipher.AEAD, iv [12]byte, sequence uint64, payload []byte, contentType byte, padding int) ([]byte, error) {
	if aead == nil || aead.NonceSize() != 12 || aead.Overhead() != 16 {
		return nil, fmt.Errorf("unsupported TLS 1.3 AEAD")
	}
	if sequence >= 0xffffffffffffff00 {
		return nil, fmt.Errorf("TLS 1.3 sequence exhausted: reconnect required")
	}
	// Reconnect before the conservative AES-GCM full-record usage bound.
	// Applying the same bound to ChaCha also keeps connection lifetimes bounded.
	if err := CheckTLSKeyUsage(sequence); err != nil {
		return nil, err
	}
	if len(payload) > 16384 || padding < 0 || len(payload)+1+padding > 16385 {
		return nil, fmt.Errorf("invalid TLS 1.3 plaintext/padding length")
	}
	innerLen := len(payload) + 1 + padding
	recordLen := innerLen + aead.Overhead()
	needed := 5 + recordLen
	start := len(b.buffer)
	if start+needed > 4*(5+16385+16) {
		return nil, fmt.Errorf("TLS record batch exceeds bounded storage")
	}
	b.buffer = slices.Grow(b.buffer, needed)[:start+needed]
	record := b.buffer[start:]
	header := record[:5]
	header[0], header[1], header[2] = 0x17, 0x03, 0x03
	binary.BigEndian.PutUint16(header[3:], uint16(recordLen))
	inner := record[5 : 5+innerLen]
	copy(inner, payload)
	inner[len(payload)] = contentType
	// Reused storage may contain an earlier ciphertext: padding MUST be zeroed.
	clear(inner[len(payload)+1:])
	sealed := aead.Seal(header, TLSNonce(&b.nonce, iv, sequence), inner, header)
	return b.buffer[:start+len(sealed)], nil
}
