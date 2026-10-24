//go:build android || (linux && atlanttest)

package atlant

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestXHTTPDeadlineInterruptsBlockedRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	conn := &http2DuplexConn{reader: reader, writer: io.Discard, closer: writer, closed: make(chan struct{})}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); done <- err }()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("deadline returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked HTTP/2 read ignored deadline")
	}
}

func TestXHTTPDeadlineInterruptsBlockedWrite(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	conn := &http2DuplexConn{reader: reader, writer: writer, closer: writer, closed: make(chan struct{})}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("blocked")); done <- err }()
	conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded without a reader")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked HTTP/2 write ignored deadline")
	}
}
