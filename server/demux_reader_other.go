//go:build !linux

package main

import "net"

func newDemuxPacketReader(conn net.PacketConn) demuxPacketReader {
	return &singleDemuxReader{conn: conn}
}
