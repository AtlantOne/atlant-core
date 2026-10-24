package wire

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const MaxUDPPacket = 65535

// UDPStreamOptions applies to the existing 2-byte-length UDP stream format.
// Each direction owns its buffers; OnResponse must consume its borrowed slice
// synchronously. Neither retries nor transport selection happen in this layer.
type UDPStreamOptions struct {
	Context    context.Context
	ReadIdle   time.Duration
	WriteIdle  time.Duration
	OnResponse func([]byte)
}

func writeUDPFrame(w io.Writer, frame []byte, n int) error {
	if n < 0 || n > MaxUDPPacket || len(frame) < n+2 {
		return errors.New("invalid UDP stream frame size")
	}
	binary.BigEndian.PutUint16(frame[:2], uint16(n))
	return WriteFull(w, frame[:n+2])
}

func readUDPPacket(r io.Reader, packet []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n > len(packet) {
		return 0, io.ErrShortBuffer
	}
	_, err := io.ReadFull(r, packet[:n])
	return n, err
}

// RelayUDPStream preserves UDP packet boundaries over an already authenticated
// QUIC/REALITY stream. It owns and closes both connections. A nil initial packet
// means none; a non-nil empty slice is a real zero-length UDP datagram.
func RelayUDPStream(packetConn, stream net.Conn, initial []byte, options UDPStreamOptions) error {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	readIdle, writeIdle := options.ReadIdle, options.WriteIdle
	if readIdle <= 0 {
		readIdle = 5 * time.Minute
	}
	if writeIdle <= 0 {
		writeIdle = 10 * time.Second
	}
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = packetConn.Close(); _ = stream.Close() }) }
	defer closeBoth()
	if len(initial) > MaxUDPPacket {
		return errors.New("initial UDP packet exceeds framing limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-done:
		}
	}()
	results := make(chan error, 2)
	go func() {
		defer closeBoth()
		frame := make([]byte, 2+MaxUDPPacket)
		var readDeadline, writeDeadline IdleDeadline
		if initial != nil {
			copy(frame[2:], initial)
			_ = writeDeadline.Update(time.Now(), writeIdle, stream.SetWriteDeadline)
			if err := writeUDPFrame(stream, frame, len(initial)); err != nil {
				results <- err
				return
			}
		}
		for {
			_ = readDeadline.Update(time.Now(), readIdle, packetConn.SetReadDeadline)
			n, err := packetConn.Read(frame[2:])
			if err != nil {
				results <- err
				return
			}
			_ = writeDeadline.Update(time.Now(), writeIdle, stream.SetWriteDeadline)
			if err := writeUDPFrame(stream, frame, n); err != nil {
				results <- err
				return
			}
		}
	}()
	go func() {
		defer closeBoth()
		packet := make([]byte, MaxUDPPacket)
		var readDeadline, writeDeadline IdleDeadline
		for {
			_ = readDeadline.Update(time.Now(), readIdle, stream.SetReadDeadline)
			n, err := readUDPPacket(stream, packet)
			if err != nil {
				results <- err
				return
			}
			_ = writeDeadline.Update(time.Now(), writeIdle, packetConn.SetWriteDeadline)
			written, err := packetConn.Write(packet[:n])
			if err == nil && written != n {
				err = io.ErrShortWrite
			}
			if err != nil {
				results <- err
				return
			}
			if options.OnResponse != nil {
				options.OnResponse(packet[:n])
			}
		}
	}()
	first := <-results
	closeBoth()
	<-results // both goroutines must finish before buffers/callbacks can escape
	if err := ctx.Err(); err != nil {
		return err
	}
	return first
}
