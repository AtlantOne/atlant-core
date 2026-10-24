//go:build linux

package main

import (
	"io"
	"net"

	"golang.org/x/net/ipv4"
)

// Batch only the kernel receive operations. Every datagram still passes through
// the original admission, replay and donor-routing checks in readLoop.
type batchDemuxReader struct {
	conn            *ipv4.PacketConn
	messages        []ipv4.Message
	position, count int
	pending         error
}

func newDemuxPacketReader(conn net.PacketConn) demuxPacketReader {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return &singleDemuxReader{conn: conn}
	}
	r := &batchDemuxReader{conn: ipv4.NewPacketConn(udp), messages: make([]ipv4.Message, 16)}
	for i := range r.messages {
		r.messages[i].Buffers = [][]byte{make([]byte, 65535)}
	}
	return r
}

func (r *batchDemuxReader) ReadPacket() ([]byte, net.Addr, error) {
	if r.position >= r.count {
		if r.pending != nil {
			return nil, nil, r.pending
		}
		r.count, r.pending = r.conn.ReadBatch(r.messages, 0)
		r.position = 0
		if r.count <= 0 {
			r.count = 0
			if r.pending == nil {
				r.pending = io.ErrNoProgress
			}
			return nil, nil, r.pending
		}
	}
	m := &r.messages[r.position]
	r.position++
	return m.Buffers[0][:m.N], m.Addr, nil
}
