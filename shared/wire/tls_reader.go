package wire

import (
	"bufio"
	"io"
)

// TLSRecordReader prefetches adjacent records so reading a TLS header and
// its ciphertext need not make separate socket reads. Its owner serializes Read.
type TLSRecordReader struct {
	reader *bufio.Reader
}

func (r *TLSRecordReader) ReadFull(source io.Reader, p []byte) (int, error) {
	if r.reader == nil {
		r.reader = bufio.NewReaderSize(source, 32<<10)
	}
	return io.ReadFull(r.reader, p)
}
