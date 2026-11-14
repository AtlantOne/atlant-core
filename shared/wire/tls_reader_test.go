package wire

import (
	"bytes"
	"io"
	"testing"
)

type countedReader struct {
	io.Reader
	reads int
}

func (r *countedReader) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

func TestTLSRecordReaderCoalescesAdjacentReads(t *testing.T) {
	const recordSize = 16384 + 17
	want := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6}, 4*recordSize)
	source := &countedReader{Reader: bytes.NewReader(want)}
	var buffered TLSRecordReader
	var got []byte
	for offset := 0; offset < len(want); {
		for _, size := range []int{5, recordSize - 5} {
			p := make([]byte, size)
			if _, err := buffered.ReadFull(source, p); err != nil {
				t.Fatal(err)
			}
			got = append(got, p...)
			offset += size
		}
	}
	if !bytes.Equal(got, want) || source.reads >= 48 {
		t.Fatalf("read %d bytes in %d underlying calls", len(got), source.reads)
	}
}
