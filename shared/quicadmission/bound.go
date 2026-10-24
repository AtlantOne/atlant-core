package quicadmission

import (
	"atlant.local/protocol/wire"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"sync"
	"time"
)

// InitialPacket reads only invariant header fields; it does not decrypt TLS.
// Wire4 registers whole datagrams, including any coalesced packets, so a
// modified ClientHello or boundary cannot reuse the original registration.
func InitialPacket(packet []byte) (bool, error) {
	if len(packet) == 0 {
		return false, ErrRejected
	}
	if packet[0]&0x80 == 0 {
		return false, nil
	}
	if len(packet) < 7 || packet[0]&0x40 == 0 {
		return false, ErrRejected
	}
	version := binary.BigEndian.Uint32(packet[1:5])
	typ := (packet[0] >> 4) & 3
	switch version {
	case 1:
		if typ != 0 {
			return false, nil
		}
	case 0x6b3343cf:
		if typ != 1 {
			return false, nil
		}
	default:
		return false, ErrRejected
	}
	if len(packet) < 1200 || len(packet) > 65535 {
		return true, ErrRejected
	}
	dcil := int(packet[5])
	if dcil < 8 || dcil > 20 || len(packet) < 7+dcil || packet[6+dcil] != 0 {
		return true, ErrRejected
	}
	return true, nil
}

// One socket carries exactly one wire4 connection. No public client CID is
// needed for demultiplexing, and no admission token is embedded in a header.
type ZeroCIDGenerator struct{}

func (*ZeroCIDGenerator) ConnectionIDLen() int { return 0 }
func (*ZeroCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionID{}, nil
}

func PacketDigest(packet []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("atlant/quic/initial-datagram/4\x00"))
	h.Write(packet)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// BoundPacketConn adds an authenticated control exchange to Initial sends,
// never to established 1-RTT traffic. It does not mutate UDP bytes. Each new
// retransmission is registered before release; unavailable control fails closed.
// This adds handshake RTTs, not a claim of browser-compatible QUIC behavior.
type BoundPacketConn struct {
	net.PacketConn
	control net.Conn
	token   Token
	mu      sync.Mutex
	once    sync.Once
	stop    func() bool
	flight  *flightRegistration
}

func FetchBoundPool(ctx context.Context, control net.Conn, socket net.PacketConn) (*CIDPool, *BoundPacketConn, error) {
	return FetchBoundPoolVersion(ctx, control, socket, 4)
}

func FetchBoundPoolVersion(ctx context.Context, control net.Conn, socket net.PacketConn, version byte) (*CIDPool, *BoundPacketConn, error) {
	if version != 4 && version != 6 {
		control.Close()
		return nil, nil, ErrOptions
	}
	deadline := time.Now().Add(10 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = control.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	pool, err := fetchPool(control, version)
	if err != nil {
		stop()
		control.Close()
		return nil, nil, err
	}
	cid, err := pool.GenerateConnectionID()
	if err != nil {
		stop()
		control.Close()
		return nil, nil, err
	}
	token, err := ParseToken(cid.Bytes())
	if err != nil {
		stop()
		control.Close()
		return nil, nil, err
	}
	bound := &BoundPacketConn{PacketConn: socket, control: control, token: token, stop: stop}
	if version == 6 {
		bound.startFlightRegistration(ctx)
	}
	return pool, bound, nil
}

func (c *BoundPacketConn) CloseBootstrap() {
	c.once.Do(func() {
		if c.flight != nil {
			close(c.flight.done)
		}
		c.stop()
		_ = c.control.Close()
	})
}

func (c *BoundPacketConn) Close() error {
	c.CloseBootstrap()
	return c.PacketConn.Close()
}

func (c *BoundPacketConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	initial, err := InitialPacket(packet)
	if err != nil {
		return 0, err
	}
	if initial {
		if c.flight != nil {
			return c.queueInitial(packet, addr)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		digest := PacketDigest(packet)
		frame := append([]byte{1}, c.token[:]...)
		frame = append(frame, digest[:]...)
		if err := wire.WriteFull(c.control, frame); err != nil {
			return 0, ErrRejected
		}
		var ack [1]byte
		if _, err := io.ReadFull(c.control, ack[:]); err != nil || ack[0] != 0 {
			return 0, ErrRejected
		}
	}
	return c.PacketConn.WriteTo(packet, addr)
}

// ServeBoundRegistrations runs only inside a mutually authenticated wire4
// REALITY connection. The caller must set a finite connection deadline.
func ServeBoundRegistrations(conn net.Conn, store *Store, subject string, batches ...Batch) error {
	var selected Token
	selectedSet := false
	for i := 0; i < BoundBatchSize*MaxPacketsPerToken; i++ {
		var frame [1 + TokenSize + 32]byte
		if _, err := io.ReadFull(conn, frame[:]); err != nil {
			return err
		}
		if frame[0] != 1 {
			return ErrRejected
		}
		var token Token
		var digest [32]byte
		copy(token[:], frame[1:1+TokenSize])
		copy(digest[:], frame[1+TokenSize:])
		if len(batches) > 0 {
			if selectedSet && token != selected {
				return ErrRejected
			}
			if !selectedSet {
				if err := store.RetainBoundToken(subject, batches[0].Tokens, token); err != nil {
					return err
				}
				selected = token
				selectedSet = true
			}
		}
		if err := store.RegisterPacket(subject, token, digest); err != nil {
			return err
		}
		if err := wire.WriteFull(conn, []byte{0}); err != nil {
			return err
		}
	}
	return ErrCapacity
}
