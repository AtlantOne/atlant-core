package quicpeer

import (
	"atlant.local/protocol/wire"
	"context"
	"io"
	"net"
	"time"
)

type BulkStream struct {
	ClientStream
	lease         *CarrierLease
	local, remote net.Addr
	Pace          func(int)
}

func (s *BulkStream) LocalAddr() net.Addr  { return wire.StreamAddr(s.local) }
func (s *BulkStream) RemoteAddr() net.Addr { return wire.StreamAddr(s.remote) }
func (s *BulkStream) CloseWrite() error    { return s.ClientStream.Close() }
func (s *BulkStream) Close() error {
	s.ClientStream.CancelRead(0)
	s.ClientStream.CancelWrite(0)
	s.lease.Release()
	return nil
}

// Bound each application write without a batching timer. QUIC's stream
// scheduler can interleave other streams between these writes.
func (s *BulkStream) Write(p []byte) (int, error) {
	written := 0
	s.lease.Pending(len(p))
	defer s.lease.Pending(-len(p))
	for len(p) > 0 {
		next := min(len(p), 32<<10)
		if s.Pace != nil {
			s.Pace(next)
		}
		started := time.Now()
		n, err := s.ClientStream.Write(p[:next])
		s.lease.ObserveWrite(time.Since(started))
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n != next {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func OpenBulkStream(ctx context.Context, pool *StreamPool, profile DirectProfile, limit int, open func(context.Context, *net.UDPAddr) (net.PacketConn, error), destination string, tag [4]byte, minPadding, maxPadding int) (*BulkStream, error) {
	lease, err := pool.Acquire(ctx, profile.PoolKey(), limit, func(ctx context.Context) (*Carrier, error) { return DialDirectCarrier(ctx, profile, open) })
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			lease.Release()
		}
	}()
	openCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := lease.Conn.OpenStreamSync(openCtx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(openCtx, func() { stream.CancelRead(0); stream.CancelWrite(0) })
	defer stop()
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err = wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: tag, Protocol: 0x11, Destination: destination}, minPadding, maxPadding); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	if err = openCtx.Err(); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	transferred = true
	return &BulkStream{ClientStream: stream, lease: lease, local: lease.Conn.LocalAddr(), remote: lease.Conn.RemoteAddr()}, nil
}
