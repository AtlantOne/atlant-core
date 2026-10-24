package quicadmission

import (
	"atlant.local/protocol/wire"
	"context"
	"io"
	"net"
	"time"
)

type queuedInitial struct {
	packet []byte
	addr   net.Addr
}
type flightRegistration struct {
	queue chan queuedInitial
	done  chan struct{}
}

func (c *BoundPacketConn) startFlightRegistration(ctx context.Context) {
	c.flight = &flightRegistration{queue: make(chan queuedInitial, 16), done: make(chan struct{})}
	go c.registerFlights(ctx)
}

// The socket owns a copy until the authenticated batch ACK arrives. The QUIC
// sender can enqueue its whole flight without waiting a TCP RTT per datagram.
// A bounded 1ms flush also handles single-packet retransmissions.
func (c *BoundPacketConn) queueInitial(packet []byte, addr net.Addr) (int, error) {
	select {
	case <-c.flight.done:
		return 0, ErrRejected
	default:
	}
	item := queuedInitial{append([]byte(nil), packet...), addr}
	select {
	case c.flight.queue <- item:
		return len(packet), nil
	case <-c.flight.done:
		return 0, ErrRejected
	default:
		return 0, ErrCapacity
	}
}

func (c *BoundPacketConn) registerFlights(ctx context.Context) {
	abort := func() {
		select {
		case <-c.flight.done:
			return
		default:
			_ = c.Close()
		}
	}
	for {
		var first queuedInitial
		select {
		case <-c.flight.done:
			return
		case <-ctx.Done():
			abort()
			return
		case first = <-c.flight.queue:
		}
		batch := []queuedInitial{first}
		timer := time.NewTimer(time.Millisecond)
	collect:
		for len(batch) < 8 {
			select {
			case <-c.flight.done:
				timer.Stop()
				return
			case <-ctx.Done():
				timer.Stop()
				abort()
				return
			case <-timer.C:
				break collect
			case item := <-c.flight.queue:
				batch = append(batch, item)
			}
		}
		timer.Stop()
		frame := append([]byte{2, byte(len(batch))}, c.token[:]...)
		for _, item := range batch {
			digest := PacketDigest(item.packet)
			frame = append(frame, digest[:]...)
		}
		if err := wire.WriteFull(c.control, frame); err != nil {
			abort()
			return
		}
		var ack [1]byte
		if _, err := io.ReadFull(c.control, ack[:]); err != nil || ack[0] != 0 {
			abort()
			return
		}
		for _, item := range batch {
			if _, err := c.PacketConn.WriteTo(item.packet, item.addr); err != nil {
				abort()
				return
			}
		}
	}
}

func ServeBoundFlightRegistrations(conn net.Conn, store *Store, subject string, batch Batch) error {
	if len(batch.Tokens) != 1 {
		return ErrOptions
	}
	for count := 0; count < MaxPacketsPerToken; {
		var header [2 + TokenSize]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return err
		}
		n := int(header[1])
		if header[0] != 2 || n < 1 || n > 8 || n > MaxPacketsPerToken-count {
			return ErrRejected
		}
		var token Token
		copy(token[:], header[2:])
		if token != batch.Tokens[0] {
			return ErrRejected
		}
		digests := make([][32]byte, n)
		for i := range digests {
			if _, err := io.ReadFull(conn, digests[i][:]); err != nil {
				return err
			}
		}
		for _, digest := range digests {
			if err := store.RegisterPacket(subject, token, digest); err != nil {
				return err
			}
		}
		if err := wire.WriteFull(conn, []byte{0}); err != nil {
			return err
		}
		count += n
	}
	return ErrCapacity
}
