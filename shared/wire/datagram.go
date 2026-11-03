package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// DatagramFragmentsSupported is carried in the encrypted destination-length
// field. The server only fragments replies for clients advertising support.
const DatagramFragmentsSupported uint16 = 0x4000
const DatagramDestinationMask uint16 = 0x3fff
const maxTunnelDatagram = 10 + 512 + MaxUDPPacket

var datagramSequence atomic.Uint64

func init() {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}
	datagramSequence.Store(binary.BigEndian.Uint64(seed[:]))
}

// SendTunnelDatagram leaves small packets unchanged. Oversized packets are
// fragmented inside encrypted QUIC DATAGRAM frames, without replacing the
// destination UDP socket or introducing stream retransmission delays.
func SendTunnelDatagram(packet []byte, lengthOffset int, send func([]byte) error) error {
	if lengthOffset < 0 || len(packet) < lengthOffset+2 || len(packet) > maxTunnelDatagram {
		return errors.New("invalid tunnel datagram")
	}
	// Some stacks accept DATAGRAM payloads that their packet packer cannot
	// fit at the current PMTU. Stay below the QUIC minimum-MTU packet budget,
	// including the encrypted packet header and DATAGRAM frame overhead.
	var err error
	if len(packet) <= 1150 {
		err = send(packet)
	} else {
		err = &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
	}
	for attempt := 0; attempt < 3 && err != nil; attempt++ {
		var size *quic.DatagramTooLargeError
		if !errors.As(err, &size) {
			return err
		}
		header := lengthOffset + 2
		limit := min(1150, int(size.MaxDatagramPayloadSize))
		chunk := limit - header - 16
		if chunk <= 0 || limit > maxTunnelDatagram {
			return err
		}
		id := datagramSequence.Add(1)
		err = nil
		for offset := 0; offset < len(packet)-header; offset += chunk {
			n := min(chunk, len(packet)-header-offset)
			frame := make([]byte, header+16+n)
			copy(frame, packet[:header])
			frame[lengthOffset] |= 0x80
			binary.BigEndian.PutUint64(frame[header:], id)
			binary.BigEndian.PutUint32(frame[header+8:], uint32(len(packet)-header))
			binary.BigEndian.PutUint32(frame[header+12:], uint32(offset))
			copy(frame[header+16:], packet[header+offset:header+offset+n])
			if err = send(frame); err != nil {
				break
			}
		}
	}
	return err
}

type datagramAssembly struct {
	header     []byte
	data, seen []byte
	received   int
	expires    time.Time
}

// DatagramAssembler is owned by one receive loop. Incomplete packets are
// bounded by both count and memory, and discarded after three seconds.
type DatagramAssembler struct {
	packets map[string]*datagramAssembly
	bytes   int
}

func (a *DatagramAssembler) Decode(packet []byte, lengthOffset int, now time.Time) ([]byte, bool) {
	header := lengthOffset + 2
	if lengthOffset < 0 || len(packet) < header {
		return nil, false
	}
	if packet[lengthOffset]&0x80 == 0 {
		return packet, true
	}
	if len(packet) < header+17 {
		return nil, false
	}
	for key, entry := range a.packets {
		if !now.Before(entry.expires) {
			a.bytes -= len(entry.data) * 2
			delete(a.packets, key)
		}
	}
	total := int(binary.BigEndian.Uint32(packet[header+8:]))
	offset := int(binary.BigEndian.Uint32(packet[header+12:]))
	payload := packet[header+16:]
	destLen := int(binary.BigEndian.Uint16(packet[lengthOffset:header]) & DatagramDestinationMask)
	if total < destLen || total > maxTunnelDatagram-header || destLen < 1 || destLen > 512 || offset < 0 || offset > total || len(payload) > total-offset {
		return nil, false
	}
	key := string(packet[:header]) + string(packet[header:header+8])
	entry := a.packets[key]
	if entry == nil {
		if len(a.packets) >= 128 || a.bytes+total*2 > 8*1024*1024 {
			return nil, false
		}
		if a.packets == nil {
			a.packets = make(map[string]*datagramAssembly)
		}
		entry = &datagramAssembly{header: append([]byte(nil), packet[:header]...), data: make([]byte, total), seen: make([]byte, total), expires: now.Add(3 * time.Second)}
		entry.header[lengthOffset] &= 0x7f
		a.packets[key] = entry
		a.bytes += total * 2
	}
	if len(entry.data) != total {
		return nil, false
	}
	for i, b := range payload {
		pos := offset + i
		if entry.seen[pos] != 0 {
			if entry.data[pos] != b {
				return nil, false
			}
		} else {
			entry.data[pos] = b
			entry.seen[pos] = 1
			entry.received++
		}
	}
	if entry.received != total {
		return nil, false
	}
	delete(a.packets, key)
	a.bytes -= total * 2
	return append(entry.header, entry.data...), true
}
