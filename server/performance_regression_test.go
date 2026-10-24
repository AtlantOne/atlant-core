package main

import (
	"atlant.local/protocol/wire"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type performanceConn struct {
	bytes.Buffer
	fail    bool
	writes  int
	discard bool
}

func (c *performanceConn) Write(p []byte) (int, error) {
	c.writes++
	if c.fail {
		return min(3, len(p)), io.ErrClosedPipe
	}
	if c.discard {
		return len(p), nil
	}
	return c.Buffer.Write(p)
}
func (c *performanceConn) Close() error                     { return nil }
func (c *performanceConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *performanceConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *performanceConn) SetDeadline(time.Time) error      { return nil }
func (c *performanceConn) SetReadDeadline(time.Time) error  { return nil }
func (c *performanceConn) SetWriteDeadline(time.Time) error { return nil }

func TestRealityWriteFailureIsTerminal(t *testing.T) {
	raw := &performanceConn{fail: true}
	key := make([]byte, 16)
	iv := make([]byte, 12)
	c, e := newRealityConn(raw, 0x1301, key, iv, key, iv, nil, nil, nil, nil, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write([]byte("first")); e == nil {
		t.Fatal("failed socket write accepted")
	}
	writes := raw.writes
	if _, e = c.Write([]byte("different plaintext")); e == nil || raw.writes != writes {
		t.Fatal("continued writing a broken TLS stream")
	}
}

func TestPlainTCPRetainsRecordWrites(t *testing.T) {
	raw := &performanceConn{}
	key, iv := make([]byte, 16), make([]byte, 12)
	c, err := newRealityConn(raw, 0x1301, key, iv, key, iv, nil, nil, nil, nil, 12, 12)
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
	c, err := newRealityConn(raw, 0x1301, key, iv, key, iv, nil, nil, nil, nil, 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &bufferedConn{Conn: c}
	wrapped.enableXHTTPBatching()
	if !c.xhttpBatch {
		t.Fatal("XHTTP policy lost behind protocol-peek wrapper")
	}
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

func TestQUICGSOKeepsSourceCIDRegistration(t *testing.T) {
	d := &DemuxPacketConn{authCIDs: NewShardedAuthMap()}
	// Two separate long-header datagrams. Register SCIDs, never peer DCIDs.
	first := []byte{0xc0, 0, 0, 0, 1, 2, 'd', '1', 2, 's', '1'}
	second := []byte{0xc0, 0, 0, 0, 1, 2, 'd', '2', 2, 's', '2'}
	d.QUICBeforeSend(append(first, second...), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, uint16(len(first)))
	now := time.Now()
	for _, cid := range []string{"s1", "s2"} {
		if !d.authCIDs.RefreshExisting(cid, now, time.Minute) {
			t.Fatalf("source CID %q lost", cid)
		}
	}
	for _, cid := range []string{"d1", "d2"} {
		if d.authCIDs.RefreshExisting(cid, now, time.Minute) {
			t.Fatalf("peer CID %q admitted", cid)
		}
	}
}

type countingHTTPWriter struct {
	bytes.Buffer
	writes, flushes int
}

func (w *countingHTTPWriter) Write(p []byte) (int, error) { w.writes++; return w.Buffer.Write(p) }
func (w *countingHTTPWriter) Flush()                      { w.flushes++ }
func TestXHTTPDoesNotManuallyFragmentHTTP2Frames(t *testing.T) {
	w := &countingHTTPWriter{}
	c := &http2DuplexConn{writer: w, flusher: w, closed: make(chan struct{})}
	data := make([]byte, 65536)
	if n, err := c.Write(data); err != nil || n != len(data) {
		t.Fatalf("write %d %v", n, err)
	}
	if w.writes != 1 || w.flushes != 1 {
		t.Fatalf("redundant writes/flushes: %d/%d", w.writes, w.flushes)
	}
	if _, err := c.Write([]byte{1}); err != nil || w.flushes != 2 {
		t.Fatal("small response not flushed immediately")
	}
}

func TestRealityLegacyReadAndSmallBuffers(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	legacy := bytes.Repeat([]byte{2}, 16)
	iv := make([]byte, 12)
	raw := &performanceConn{}
	aead, e := createTLS13AEAD(0x1301, legacy)
	if e != nil {
		t.Fatal(e)
	}
	var buffer wire.TLSRecordBuffer
	payload := bytes.Repeat([]byte("abcdefghijk"), 3000)
	var expected []byte
	for seq := uint64(0); seq < 2; seq++ {
		p := payload[:12000+int(seq)]
		record, e := buffer.Seal(aead, [12]byte{}, seq, p, 0x17, 32)
		if e != nil {
			t.Fatal(e)
		}
		raw.Buffer.Write(record)
		expected = append(expected, p...)
	}
	c, e := newRealityConn(raw, 0x1301, key, iv, key, iv, legacy, iv, legacy, iv, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 0, len(expected))
	small := make([]byte, 7)
	for len(got) < len(expected) {
		n, e := c.Read(small)
		got = append(got, small[:n]...)
		if e != nil {
			t.Fatal(e)
		}
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("retained decrypt data was overwritten")
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

func TestAuthRefreshCannotReviveExpiredCID(t *testing.T) {
	m := NewShardedAuthMap()
	now := time.Now()
	m.Set("expired", now.Add(-6*time.Minute))
	m.Set("valid", now.Add(-time.Minute))
	if m.RefreshExisting("unknown", now, 5*time.Minute) || m.RefreshExisting("expired", now, 5*time.Minute) {
		t.Fatal("revived unknown/expired authorization")
	}
	if !m.RefreshExisting("valid", now, 5*time.Minute) {
		t.Fatal("valid CID not refreshed")
	}
}

func BenchmarkRealityRecordWrite(b *testing.B) {
	raw := &performanceConn{discard: true}
	key := make([]byte, 16)
	iv := make([]byte, 12)
	c, e := newRealityConn(raw, 0x1301, key, iv, key, iv, nil, nil, nil, nil, 0, 0)
	if e != nil {
		b.Fatal(e)
	}
	data := make([]byte, 65536)
	for range 8 {
		_, _ = c.Write(data)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, e = c.Write(data); e != nil {
			b.Fatal(e)
		}
	}
}
