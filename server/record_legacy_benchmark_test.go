package main

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
)

type legacyRecordConn struct {
	net.Conn
	encCipher cipher.AEAD
	encNonce  uint64
	encIV     [12]byte
	writeMu   sync.Mutex
}

var legacyRecordWritePool = sync.Pool{New: func() any { b := make([]byte, 5, 5+16384+16+256); return &b }}

// Exact pre-optimization writer recovered from the source backup, for local
// microbenchmark comparison only. Never linked into a production executable.
func (c *legacyRecordConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxPlaintext = 16384
	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxPlaintext {
			chunkSize = maxPlaintext
		}
		chunk := p[:chunkSize]

		padLen := 0
		if c.encNonce < 12 || chunkSize < 900 {
			var rnd [1]byte
			_, _ = rand.Read(rnd[:])
			padLen = 16 + int(rnd[0])%112 // 16..127 bytes random RFC 8446 padding
			if chunkSize+1+padLen > maxPlaintext {
				padLen = 0
			}
		}

		// RFC 8446 Section 5.4: TLSInnerPlaintext wraps content with trailing ContentType (0x17) and padding zeros
		innerPlaintext := make([]byte, chunkSize+1+padLen)
		copy(innerPlaintext, chunk)
		innerPlaintext[chunkSize] = 0x17
		recordLen := len(innerPlaintext) + 16

		// Nonce overflow guard (RFC 8446 Section 5.3)
		if c.encNonce >= 0xFFFFFFFFFFFFFF00 {
			return total, fmt.Errorf("TLS 1.3 sequence number overflow: connection must be terminated")
		}

		nonce := makeTLS13Nonce(c.encIV, c.encNonce)
		c.encNonce++

		bufPtr := legacyRecordWritePool.Get().(*[]byte)
		header := (*bufPtr)[:5]
		header[0] = 0x17
		header[1] = 0x03
		header[2] = 0x03
		header[3] = byte(recordLen >> 8)
		header[4] = byte(recordLen)

		// header is dst (capacity is 5+16384+16), Seal appends ciphertext + tag to header
		ciphertext := c.encCipher.Seal(header, nonce, innerPlaintext, header)
		err := writeFull(c.Conn, ciphertext)
		legacyRecordWritePool.Put(bufPtr)
		if err != nil {
			return total, err
		}
		total += chunkSize
		p = p[chunkSize:]
	}
	return total, nil
}

func BenchmarkLegacyRealityRecordWrite(b *testing.B) {
	raw := &performanceConn{discard: true}
	key := make([]byte, 16)
	aead, e := createTLS13AEAD(0x1301, key)
	if e != nil {
		b.Fatal(e)
	}
	c := &legacyRecordConn{Conn: raw, encCipher: aead}
	data := make([]byte, 65536)
	for range 8 {
		_, _ = c.Write(data)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, e = c.Write(data); e != nil {
			b.Fatal(e)
		}
	}
}
