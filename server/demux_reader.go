package main

import "net"

type demuxPacketReader interface {
	ReadPacket() ([]byte, net.Addr, error)
}

type singleDemuxReader struct {
	conn   net.PacketConn
	buffer [65535]byte
}

func (r *singleDemuxReader) ReadPacket() ([]byte, net.Addr, error) {
	n, peer, err := r.conn.ReadFrom(r.buffer[:])
	return r.buffer[:n], peer, err
}
