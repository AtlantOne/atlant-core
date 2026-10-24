package wire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
)

func TestTLSKeyUsageBoundary(t *testing.T) {
	if err := CheckTLSKeyUsage(TLSMaxRecordsPerKey - 1); err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{TLSMaxRecordsPerKey, TLSMaxRecordsPerKey + 1, ^uint64(0)} {
		if CheckTLSKeyUsage(sequence) == nil {
			t.Fatalf("exhausted key accepted at sequence %d", sequence)
		}
	}
}

func TestTLSBatchIsIdenticalToSeparateRecords(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	var batch, single TLSRecordBuffer
	var want, got []byte
	for i := range 4 {
		payload := bytes.Repeat([]byte{byte(i)}, 16000)
		p, err := single.Seal(aead, [12]byte{}, uint64(i), payload, 0x17, i*13)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, p...)
		got, err = batch.AppendSeal(aead, [12]byte{}, uint64(i), payload, 0x17, i*13)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatal("batch changed encrypted records")
	}
	if _, err := batch.AppendSeal(aead, [12]byte{}, 4, make([]byte, 16384), 0x17, 0); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	batch.ResetBatch()
	got, err := batch.AppendSeal(aead, [12]byte{}, 5, []byte("small"), 0x17, 16)
	if err != nil {
		t.Fatal(err)
	}
	want, _ = single.Seal(aead, [12]byte{}, 5, []byte("small"), 0x17, 16)
	if !bytes.Equal(got, want) {
		t.Fatal("batch retained old data")
	}
}

func TestTLSRecordBufferPreservesWireBytes(t *testing.T) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{7}, 16))
	gcm, _ := cipher.NewGCM(block)
	block256, _ := aes.NewCipher(bytes.Repeat([]byte{8}, 32))
	gcm256, _ := cipher.NewGCM(block256)
	chacha, _ := chacha20poly1305.New(bytes.Repeat([]byte{9}, 32))
	for _, aead := range []cipher.AEAD{gcm, gcm256, chacha} {
		var b TLSRecordBuffer
		iv := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		for _, size := range []int{0, 1, 899, 900, 16383, 16384} {
			for _, padding := range []int{0, 16, 127} {
				if size+1+padding > 16385 {
					continue
				}
				payload := bytes.Repeat([]byte{0xab}, size)
				for _, seq := range []uint64{0, 11, 12, 12345} {
					got, e := b.Seal(aead, iv, seq, payload, 0x17, padding)
					if e != nil {
						t.Fatal(e)
					}
					inner := make([]byte, size+1+padding)
					copy(inner, payload)
					inner[size] = 0x17
					header := []byte{0x17, 3, 3, 0, 0}
					binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+16))
					nonce := iv
					binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(iv[4:])^seq)
					want := aead.Seal(append([]byte(nil), header...), nonce[:], inner, header)
					if !bytes.Equal(got, want) {
						t.Fatalf("wire changed: size=%d pad=%d seq=%d", size, padding, seq)
					}
				}
			}
		}
	}
}
func TestTLSRecordBufferRejectsOverflow(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	var b TLSRecordBuffer
	if _, e := b.Seal(aead, [12]byte{}, 0xffffffffffffff00, []byte("secret"), 0x17, 0); e == nil {
		t.Fatal("sequence overflow accepted")
	}
	if _, e := b.Seal(aead, [12]byte{}, 0, make([]byte, 16384), 0x17, 1); e == nil {
		t.Fatal("oversize padding accepted")
	}
}
func BenchmarkTLSRecordBuffer(b *testing.B) {
	block, _ := aes.NewCipher(make([]byte, 16))
	aead, _ := cipher.NewGCM(block)
	var record TLSRecordBuffer
	payload := make([]byte, 16384)
	_, _ = record.Seal(aead, [12]byte{}, 0, payload, 0x17, 0)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, e := record.Seal(aead, [12]byte{}, uint64(i), payload, 0x17, 0)
		if e != nil {
			b.Fatal(e)
		}
	}
}

func TestTLSRecordBufferNoAllocAfterWarmup(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 32))
	aead, _ := cipher.NewGCM(block)
	var record TLSRecordBuffer
	payload := make([]byte, 16384)
	seq := uint64(0)
	_, _ = record.Seal(aead, [12]byte{}, seq, payload, 0x17, 0)
	allocs := testing.AllocsPerRun(1000, func() {
		seq++
		if _, err := record.Seal(aead, [12]byte{}, seq, payload, 0x17, 0); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("record writer regressed to %.2f allocations per record", allocs)
	}
}
