package wire

import (
	"bytes"
	"io"
	"testing"
)

func TestLargePaddingPreservesPayloadBoundary(t *testing.T) {
	header := QUICHeader{[4]byte{1, 2, 3, 4}, 0x12, "[2001:db8::1]:53"}
	var stream bytes.Buffer
	if err := WriteQUICHeader(&stream, header, 2048, 2048); err != nil {
		t.Fatal(err)
	}
	stream.WriteString("payload")
	got, err := ReadQUICHeader(&stream)
	if err != nil || got != header {
		t.Fatalf("header=%v error=%v", got, err)
	}
	remaining, _ := io.ReadAll(&stream)
	if string(remaining) != "payload" {
		t.Fatal("padding became payload")
	}
}

func TestTruncatedPaddingRejected(t *testing.T) {
	var stream bytes.Buffer
	if err := WriteQUICHeader(&stream, QUICHeader{Protocol: 0x11, Destination: "host:443"}, 20, 20); err != nil {
		t.Fatal(err)
	}
	data := stream.Bytes()
	if _, err := ReadQUICHeader(bytes.NewReader(data[:len(data)-1])); err == nil {
		t.Fatal("truncated header accepted")
	}
}

func TestOutOfRangePaddingRejectedBeforeWrite(t *testing.T) {
	var stream bytes.Buffer
	if err := WriteQUICHeader(&stream, QUICHeader{Protocol: 0x11, Destination: "host:443"}, 0, 65536); err == nil {
		t.Fatal("padding overflow accepted")
	}
	if stream.Len() != 0 {
		t.Fatal("invalid header partially transmitted")
	}
}

func FuzzReadQUICHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0x11, 0, 1, 'a', 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadQUICHeader(bytes.NewReader(data)) })
}
