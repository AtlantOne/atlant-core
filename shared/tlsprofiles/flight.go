package tlsprofiles

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteClientHello preserves every handshake byte, but bounds TLS record
// payloads. Large modern key shares make a ClientHello exceed a single network
// segment; some paths stall its continuation. This changes record framing,
// not extensions, authentication, the TLS transcript or negotiated key groups.
// It is a compatibility policy, not a claim of Chrome-identical record sizes.
func WriteClientHello(writer io.Writer, record []byte) error {
	if len(record) < 9 || len(record) > 16389 || record[0] != 22 || record[1] != 3 || record[2] > 3 ||
		int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 || record[5] != 1 ||
		(int(record[6])<<16|int(record[7])<<8|int(record[8])) != len(record)-9 {
		return fmt.Errorf("invalid initial ClientHello record")
	}
	const maximumPayload = 1024
	write := func(data []byte) error {
		for len(data) > 0 {
			n, err := writer.Write(data)
			if n < 0 || n > len(data) {
				return io.ErrShortWrite
			}
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			data = data[n:]
		}
		return nil
	}
	if len(record)-5 <= maximumPayload {
		return write(record)
	}
	// Enqueue the complete flight in one socket write. Separate writes expose
	// a gap after the first TLS record; record framing and transcript stay exact.
	count := (len(record) - 5 + maximumPayload - 1) / maximumPayload
	flight := make([]byte, 0, len(record)+5*(count-1))
	for payload := record[5:]; len(payload) > 0; {
		n := len(payload)
		if n > maximumPayload {
			n = maximumPayload
		}
		flight = append(flight, record[:3]...)
		flight = append(flight, byte(n>>8), byte(n))
		flight = append(flight, payload[:n]...)
		payload = payload[n:]
	}
	return write(flight)
}
