package tlsprofiles

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type partialHelloWriter struct {
	bytes.Buffer
	limit int
}

func (w *partialHelloWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

type failingHelloWriter struct{ err error }

func (w failingHelloWriter) Write(p []byte) (int, error) { return 0, w.err }

func helloRecord(size int) []byte {
	record := make([]byte, 5+size)
	copy(record, []byte{22, 3, 1})
	binary.BigEndian.PutUint16(record[3:5], uint16(size))
	record[5] = 1
	n := size - 4
	record[6] = byte(n >> 16)
	record[7] = byte(n >> 8)
	record[8] = byte(n)
	for i := 9; i < len(record); i++ {
		record[i] = byte(i)
	}
	return record
}

func TestHelloFramingPreservesExactTranscriptAndSmallRecords(t *testing.T) {
	for _, size := range []int{537, 1024, 1025, 1791, 4096, 16384} {
		source := helloRecord(size)
		writer := &partialHelloWriter{limit: 17}
		if err := WriteClientHello(writer, source); err != nil {
			t.Fatal(err)
		}
		if size <= 1024 && !bytes.Equal(source, writer.Bytes()) {
			t.Fatal("small ClientHello was changed")
		}
		var payload []byte
		records := 0
		for wire := writer.Bytes(); len(wire) > 0; records++ {
			if len(wire) < 5 {
				t.Fatal("truncated record")
			}
			n := int(binary.BigEndian.Uint16(wire[3:5]))
			if n > 1024 || n == 0 || len(wire) < 5+n || !bytes.Equal(wire[:3], source[:3]) {
				t.Fatal("bad record framing")
			}
			payload = append(payload, wire[5:5+n]...)
			wire = wire[5+n:]
		}
		if !bytes.Equal(payload, source[5:]) {
			t.Fatal("TLS transcript changed")
		}
		if records != (size+1023)/1024 {
			t.Fatal("unexpected fragment count")
		}
	}
}

func TestHelloFramingRejectsMalformedInputAndPropagatesWriteFailure(t *testing.T) {
	for _, record := range [][]byte{nil, helloRecord(4)[:8], append(helloRecord(537), 0), {23, 3, 1, 0, 4, 1, 0, 0, 0}} {
		var out bytes.Buffer
		if err := WriteClientHello(&out, record); err == nil || out.Len() != 0 {
			t.Fatal("malformed input was written")
		}
	}
	sentinel := errors.New("socket failed")
	if !errors.Is(WriteClientHello(failingHelloWriter{sentinel}, helloRecord(1791)), sentinel) {
		t.Fatal("write error lost")
	}
	if !errors.Is(WriteClientHello(failingHelloWriter{}, helloRecord(1791)), io.ErrShortWrite) {
		t.Fatal("zero progress accepted")
	}
}
