package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type performanceConn struct {
	bytes.Buffer
	fail   bool
	writes int
}

func (c *performanceConn) Write(p []byte) (int, error) {
	c.writes++
	if c.fail {
		return min(3, len(p)), io.ErrClosedPipe
	}
	return c.Buffer.Write(p)
}
func (c *performanceConn) Close() error                     { return nil }
func (c *performanceConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *performanceConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *performanceConn) SetDeadline(time.Time) error      { return nil }
func (c *performanceConn) SetReadDeadline(time.Time) error  { return nil }
func (c *performanceConn) SetWriteDeadline(time.Time) error { return nil }

func TestPlainTCPRetainsRecordWrites(t *testing.T) {
	raw := &performanceConn{}
	key, iv := make([]byte, 16), make([]byte, 12)
	c, err := newRealityConn(raw, 0x1301, key, iv, key, iv, 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write(make([]byte, 32768)); err != nil || n != 32768 {
		t.Fatalf("write %d %v", n, err)
	}
	if raw.writes != 2 {
		t.Fatalf("plain TCP write policy changed: %d", raw.writes)
	}
}

func TestRealityBatchesSocketWritesWithoutChangingRecords(t *testing.T) {
	raw := &performanceConn{}
	key, iv := make([]byte, 16), make([]byte, 12)
	c, err := newRealityConn(raw, 0x1301, key, iv, key, iv, 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	c.enableXHTTPBatching()
	data := bytes.Repeat([]byte("0123456789abcdef"), 8192)
	if n, err := c.Write(data); err != nil || n != len(data) {
		t.Fatalf("write %d %v", n, err)
	}
	if raw.writes != 2 {
		t.Fatalf("expected two bounded writes, got %d", raw.writes)
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, got) {
		t.Fatal("encrypted payload changed")
	}
	if n, err := c.Write([]byte("small request")); err != nil || n != 13 {
		t.Fatalf("small write %d %v", n, err)
	}
	if raw.writes != 3 {
		t.Fatal("small request was delayed")
	}
}

func TestRealityWriteFailureIsTerminal(t *testing.T) {
	raw := &performanceConn{fail: true}
	key := make([]byte, 16)
	iv := make([]byte, 12)
	c, e := newRealityConn(raw, 0x1301, key, iv, key, iv, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write([]byte("first")); e == nil {
		t.Fatal("socket write failure accepted")
	}
	count := raw.writes
	if _, e = c.Write([]byte("different plaintext")); e == nil || raw.writes != count {
		t.Fatal("continued failed TLS stream")
	}
	if e = c.CloseWrite(); e == nil || raw.writes != count {
		t.Fatal("sent close_notify on failed TLS stream")
	}
}
func TestRealityCloseWriteIsIdempotent(t *testing.T) {
	raw := &performanceConn{}
	key := make([]byte, 16)
	iv := make([]byte, 12)
	c, e := newRealityConn(raw, 0x1301, key, iv, key, iv, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	count := raw.writes
	if e = c.CloseWrite(); e != nil || raw.writes != count {
		t.Fatal("duplicate close_notify")
	}
	if _, e = c.Write([]byte("after FIN")); e == nil {
		t.Fatal("write after CloseWrite accepted")
	}
}

type partialHTTPWriter struct{ bytes.Buffer }

func (w *partialHTTPWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:min(7, len(p))]) }
func TestXHTTPPartialWriterDoesNotLoseBytes(t *testing.T) {
	w := &partialHTTPWriter{}
	c := &http2DuplexConn{writer: w, closed: make(chan struct{})}
	data := bytes.Repeat([]byte("partial"), 5000)
	n, e := c.Write(data)
	if e != nil || n != len(data) || !bytes.Equal(w.Bytes(), data) {
		t.Fatalf("partial write lost data: %d %v", n, e)
	}
}
