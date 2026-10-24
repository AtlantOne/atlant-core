package quicreality

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

func testInitial(t testing.TB, offset uint64, data []byte, pn byte) []byte {
	t.Helper()
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	frame := quicvarint.Append(nil, 6)
	frame = quicvarint.Append(frame, offset)
	frame = quicvarint.Append(frame, uint64(len(data)))
	frame = append(frame, data...)
	if len(frame) > 1164 {
		t.Fatal("test fragment too large")
	}
	frame = append(frame, make([]byte, 1164-len(frame))...)
	header := []byte{0xc1, 0, 0, 0, 1, 8}
	header = append(header, dcid...)
	header = append(header, 0, 0)
	header = quicvarint.Append(header, 1182)
	pnOffset := len(header)
	header = append(header, 0, pn)
	key, iv, hp, err := initialKeys(1, dcid)
	if err != nil {
		t.Fatal(err)
	}
	iv[11] ^= pn
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	packet := append(bytes.Clone(header), aead.Seal(nil, iv, frame, header)...)
	protection, _ := aes.NewCipher(hp)
	var mask [16]byte
	protection.Encrypt(mask[:], packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 15
	packet[pnOffset] ^= mask[1]
	packet[pnOffset+1] ^= mask[2]
	return packet
}

func TestInitialReassemblyReorderedAndConflictingCrypto(t *testing.T) {
	hello := testHello(bytes.Repeat([]byte{9}, 32))
	var observer Observer
	tail := testInitial(t, 50, hello[50:], 2)
	head := testInitial(t, 0, hello[:50], 1)
	if _, ok := InitialID(head); !ok {
		t.Fatal("valid initial shape")
	}
	if _, err := observer.Feed(tail); !errors.Is(err, ErrIncomplete) {
		t.Fatal("tail must wait", err)
	}
	got, err := observer.Feed(head)
	if err != nil || !bytes.Equal(got, hello) {
		t.Fatal("reassembly", err)
	}
	var coalesced Observer
	if got, err := coalesced.Feed(append(bytes.Clone(tail), head...)); err != nil || !bytes.Equal(got, hello) {
		t.Fatal("coalesced Initial reassembly", err)
	}
	changed := bytes.Clone(hello[:50])
	changed[10] ^= 1
	if _, err := observer.Feed(testInitial(t, 0, changed, 3)); err == nil {
		t.Fatal("conflicting CRYPTO accepted")
	}
}

func FuzzInitialAdmissionDecoder(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add(testInitial(f, 0, testHello(bytes.Repeat([]byte{9}, 32)), 1))
	f.Fuzz(func(t *testing.T, packet []byte) {
		var observer Observer
		_, _ = InitialID(packet)
		_, _ = observer.Feed(packet)
	})
}

func FuzzInitialCryptoFrames(f *testing.F) {
	f.Add([]byte{6, 0, 1, 1})
	f.Add([]byte{2, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, p []byte) { var observer Observer; _ = observer.frames(p) })
}
