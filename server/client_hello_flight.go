package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	maxClientHelloWireBytes = 128 << 10
	maxClientHelloBytes     = 64 << 10
	maxClientHelloRecords   = 128
)

// readClientHelloFlight preserves every consumed byte for the donor path.
// One deadline and size/record limits bound unauthenticated fragmentation.
func readClientHelloFlight(conn net.Conn, timeout time.Duration) (raw, hello []byte, err error) {
	if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, err
	}
	defer conn.SetReadDeadline(time.Time{})
	for records := 0; records < maxClientHelloRecords; records++ {
		var header [5]byte
		n, readErr := io.ReadFull(conn, header[:])
		raw = append(raw, header[:n]...)
		if readErr != nil {
			return raw, hello, readErr
		}
		size := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 0x16 || header[1] != 3 || header[2] > 3 || size < 1 || size > 16384 || len(raw)+size > maxClientHelloWireBytes {
			return raw, hello, fmt.Errorf("unsupported ClientHello record")
		}
		body := make([]byte, size)
		n, readErr = io.ReadFull(conn, body)
		raw = append(raw, body[:n]...)
		if readErr != nil {
			return raw, hello, readErr
		}
		hello = append(hello, body...)
		if len(hello) < 4 {
			continue
		}
		wanted := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
		if hello[0] != 1 || wanted > maxClientHelloBytes {
			return raw, hello, fmt.Errorf("unsupported ClientHello length")
		}
		if len(hello) >= wanted {
			if len(hello) != wanted {
				return raw, hello, fmt.Errorf("trailing ClientHello data")
			}
			return raw, hello, nil
		}
	}
	return raw, hello, fmt.Errorf("ClientHello record limit exceeded")
}
