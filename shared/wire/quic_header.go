package wire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
)

type QUICHeader struct {
	UserTag     [4]byte
	Protocol    byte
	Destination string
}

func WriteQUICHeader(w io.Writer, header QUICHeader, minPadding, maxPadding int) error {
	if (header.Protocol != 0x11 && header.Protocol != 0x12) || len(header.Destination) < 1 || len(header.Destination) > 512 {
		return fmt.Errorf("invalid QUIC stream destination or protocol")
	}
	if minPadding < 0 || maxPadding < minPadding || maxPadding > 65535 {
		return fmt.Errorf("invalid QUIC padding bounds")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxPadding-minPadding+1)))
	if err != nil {
		return err
	}
	padding := minPadding + int(n.Int64())
	destination := []byte(header.Destination)
	frame := make([]byte, 9+len(destination)+padding)
	copy(frame[:4], header.UserTag[:])
	frame[4] = header.Protocol
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(destination)))
	copy(frame[7:], destination)
	binary.BigEndian.PutUint16(frame[7+len(destination):], uint16(padding))
	if _, err := io.ReadFull(rand.Reader, frame[9+len(destination):]); err != nil {
		return err
	}
	return WriteFull(w, frame)
}

func ReadQUICHeader(r io.Reader) (QUICHeader, error) {
	var result QUICHeader
	var fixed [7]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return result, err
	}
	copy(result.UserTag[:], fixed[:4])
	result.Protocol = fixed[4]
	n := int(binary.BigEndian.Uint16(fixed[5:]))
	if n < 1 || n > 512 || (result.Protocol != 0x11 && result.Protocol != 0x12) {
		return result, fmt.Errorf("invalid QUIC stream header")
	}
	destination := make([]byte, n)
	if _, err := io.ReadFull(r, destination); err != nil {
		return result, err
	}
	result.Destination = string(destination)
	var padding [2]byte
	if _, err := io.ReadFull(r, padding[:]); err != nil {
		return result, err
	}
	_, err := io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint16(padding[:])))
	return result, err
}
