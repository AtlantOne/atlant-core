package wire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type packetTestConn struct {
	in, out chan []byte
	closed  chan struct{}
	once    sync.Once
	short   bool
}

func newPacketTestConn() *packetTestConn {
	return &packetTestConn{in: make(chan []byte, 16), out: make(chan []byte, 16), closed: make(chan struct{})}
}
func (c *packetTestConn) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.EOF
	case b := <-c.in:
		if len(b) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, b), nil
	}
}
func (c *packetTestConn) Write(p []byte) (int, error) {
	if c.short && len(p) > 0 {
		return 0, nil
	}
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	case c.out <- bytes.Clone(p):
		return len(p), nil
	}
}
func (c *packetTestConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *packetTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *packetTestConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *packetTestConn) SetDeadline(time.Time) error      { return nil }
func (c *packetTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *packetTestConn) SetWriteDeadline(time.Time) error { return nil }

type fragmentedUDPStream struct{ net.Conn }

func (c fragmentedUDPStream) Write(p []byte) (int, error) {
	if len(p) > 13 {
		p = p[:13]
	}
	return c.Conn.Write(p)
}

func TestUDPStreamPreservesMediaPacketsAcrossPartialWrites(t *testing.T) {
	for _, initial := range [][]byte{nil, {}, {1, 2, 3}} {
		t.Run("initial="+string(rune('0'+len(initial))), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			packets := newPacketTestConn()
			left, right := net.Pipe()
			defer right.Close()
			_ = right.SetDeadline(time.Now().Add(5 * time.Second))
			done := make(chan error, 1)
			go func() {
				done <- RelayUDPStream(packets, fragmentedUDPStream{left}, initial, UDPStreamOptions{Context: ctx})
			}()
			go func() {
				defer right.Close()
				buf := make([]byte, MaxUDPPacket+2)
				for {
					n, err := readUDPPacket(right, buf[2:])
					if err != nil {
						return
					}
					if writeUDPFrame(fragmentedUDPStream{right}, buf, n) != nil {
						return
					}
				}
			}()
			check := func(want []byte) {
				t.Helper()
				select {
				case got := <-packets.out:
					if !bytes.Equal(got, want) {
						t.Fatalf("packet corrupted: got %d want %d", len(got), len(want))
					}
				case <-time.After(5 * time.Second):
					t.Fatal("UDP response stalled")
				}
			}
			if initial != nil {
				check(initial)
			}
			for _, size := range []int{0, 1, 17, 1200, 1350, 4096, 16384, 65507, 65535} {
				payload := bytes.Repeat([]byte{byte(size)}, size)
				packets.in <- payload
				check(payload)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("relay leaked after cancellation")
			}
		})
	}
}

func TestUDPFrameRejectsOversizeAndTruncation(t *testing.T) {
	if err := writeUDPFrame(io.Discard, make([]byte, MaxUDPPacket+3), MaxUDPPacket+1); err == nil {
		t.Fatal("oversize frame accepted")
	}
	for _, data := range [][]byte{{1}, {0, 2, 7}} {
		if _, err := readUDPPacket(bytes.NewReader(data), make([]byte, 8)); err == nil {
			t.Fatal("truncated frame accepted")
		}
	}
	if _, err := readUDPPacket(bytes.NewReader([]byte{0, 9}), make([]byte, 8)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("buffer limit=%v", err)
	}
}

func TestUDPStreamShortPacketWriteStopsBothDirections(t *testing.T) {
	packets := newPacketTestConn()
	packets.short = true
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan error, 1)
	go func() { done <- RelayUDPStream(packets, left, nil, UDPStreamOptions{}) }()
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := right.Write([]byte{0, 1, 42}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short packet write=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("short write left a stuck relay")
	}
}

func TestUDPStreamTruncatedResponseUnblocksPacketReader(t *testing.T) {
	packets := newPacketTestConn()
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- RelayUDPStream(packets, left, nil, UDPStreamOptions{}) }()
	_ = right.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = right.Write([]byte{0, 8, 42})
	_ = right.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated response=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("truncated response left upload blocked")
	}
}

func TestUDPStreamCanceledBeforeStartClosesConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	packets := newPacketTestConn()
	left, right := net.Pipe()
	defer right.Close()
	if err := RelayUDPStream(packets, left, nil, UDPStreamOptions{Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-packets.closed:
	default:
		t.Fatal("packet endpoint leaked")
	}
}

func TestUDPFrameHasUnchangedTwoBytePrefix(t *testing.T) {
	frame := append([]byte{0, 0}, bytes.Repeat([]byte{11}, 1200)...)
	var encoded bytes.Buffer
	if err := writeUDPFrame(&encoded, frame, 1200); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(encoded.Bytes()[:2]) != 1200 || !bytes.Equal(encoded.Bytes()[2:], frame[2:]) {
		t.Fatal("legacy wire format changed")
	}
}
