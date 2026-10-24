package tlsaudit

import (
	"encoding/binary"
	"testing"
)

func helloWithExtensions(extensions []byte) []byte {
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{0x16, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestAuditRejectsDuplicateExtensionsAndBadVectors(t *testing.T) {
	if _, err := Summarize(helloWithExtensions([]byte{0, 23, 0, 0})); err != nil {
		t.Fatal(err)
	}
	for _, extensions := range [][]byte{
		{0, 23, 0, 0, 0, 23, 0, 0},
		{0, 43, 0, 2, 2, 3},
		{0, 10, 0, 3, 0, 2, 0},
		{0, 57, 0, 6, 1, 1, 1, 1, 1, 2},
	} {
		if _, err := Summarize(helloWithExtensions(extensions)); err == nil {
			t.Fatal("malformed audit input accepted")
		}
	}
}

func FuzzSummarize(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x16, 3, 3, 0, 1, 1})
	f.Add(helloWithExtensions([]byte{0, 23, 0, 0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128<<10 {
			t.Skip()
		}
		if s, err := Summarize(data); err == nil {
			_ = s.StructuralKey()
		}
	})
}
