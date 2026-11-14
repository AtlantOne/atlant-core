package tlsprofiles

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteClientHello validates and sends the supplied TLS record unchanged.
// Keep the whole flight in one write when the socket accepts it, and handle
// short writes without adding TLS records or changing the transcript.
func WriteClientHello(writer io.Writer, record []byte) error {
	if len(record) < 9 || len(record) > 16389 || record[0] != 22 || record[1] != 3 || record[2] > 3 ||
		int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 || record[5] != 1 ||
		(int(record[6])<<16|int(record[7])<<8|int(record[8])) != len(record)-9 {
		return fmt.Errorf("invalid initial ClientHello record")
	}
	for len(record) > 0 {
		n, err := writer.Write(record)
		if n < 0 || n > len(record) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		record = record[n:]
	}
	return nil
}
