package atlant

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type writeFunc func([]byte) (int, error)

func (f writeFunc) Write(p []byte) (int, error) { return f(p) }

func TestWriteFullKeepsFrameAcrossPartialWrites(t *testing.T) {
	frame := append([]byte{0, 255}, bytes.Repeat([]byte{42}, 255)...)
	var received bytes.Buffer
	w := writeFunc(func(p []byte) (int, error) {
		if len(p) > 3 {
			p = p[:3]
		}
		return received.Write(p)
	})
	if err := writeFull(w, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received.Bytes(), frame) {
		t.Fatal("UDP framing was corrupted")
	}
}

func TestWriteFullRejectsNoProgress(t *testing.T) {
	err := writeFull(writeFunc(func([]byte) (int, error) { return 0, nil }), []byte{1})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteFullPropagatesPartialFailure(t *testing.T) {
	failure := errors.New("connection failed")
	err := writeFull(writeFunc(func([]byte) (int, error) { return 1, failure }), []byte{1, 2})
	if !errors.Is(err, failure) {
		t.Fatalf("got %v", err)
	}
}
