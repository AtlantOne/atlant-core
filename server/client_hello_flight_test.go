package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func helloRecord(payload []byte) []byte {
	record := []byte{0x16, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(len(payload)))
	return append(record, payload...)
}

func parserHello(suites, extensions []byte) []byte {
	body := make([]byte, 35)
	body[0], body[1] = 3, 3
	body = binary.BigEndian.AppendUint16(body, uint16(len(suites)))
	body = append(body, suites...)
	body = append(body, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return helloRecord(append(hello, body...))
}

type flightReader struct {
	*bytes.Reader
	deadlines []time.Time
}

func (c *flightReader) Write(p []byte) (int, error)      { return len(p), nil }
func (c *flightReader) Close() error                     { return nil }
func (c *flightReader) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *flightReader) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *flightReader) SetDeadline(time.Time) error      { return nil }
func (c *flightReader) SetWriteDeadline(time.Time) error { return nil }
func (c *flightReader) SetReadDeadline(value time.Time) error {
	c.deadlines = append(c.deadlines, value)
	return nil
}

func TestClientHelloFlightPreservesFragmentedAndPartialInput(t *testing.T) {
	valid := parserHello([]byte{0x13, 1}, nil)
	hello := valid[5:]
	fragmented := append(helloRecord(hello[:2]), helloRecord(hello[2:])...)
	cases := []struct {
		name  string
		input []byte
		valid bool
	}{
		{"single", valid, true}, {"split-header", fragmented, true},
		{"partial-header", []byte{0x16, 3}, false},
		{"partial-body", valid[:len(valid)-2], false},
		{"partial-next-header", append(helloRecord(hello[:4]), 0x16, 3), false},
		{"partial-next-body", append(helloRecord(hello[:4]), helloRecord(hello[4:])[:8]...), false},
		{"non-handshake", []byte{0x17, 3, 3, 0, 8}, false},
		{"oversized-message", helloRecord([]byte{1, 0xff, 0xff, 0xff}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &flightReader{Reader: bytes.NewReader(tc.input)}
			raw, got, err := readClientHelloFlight(conn, time.Second)
			if (err == nil) != tc.valid || !bytes.Equal(raw, tc.input) {
				t.Fatal("flight changed or validity mismatch", err)
			}
			if tc.valid && !bytes.Equal(got, hello) {
				t.Fatal("handshake transcript changed")
			}
			if len(conn.deadlines) != 2 || !conn.deadlines[1].IsZero() {
				t.Fatal("deadline extended per fragment or not reset")
			}
		})
	}
}

func TestClientHelloFlightRecordLimit(t *testing.T) {
	input := helloRecord([]byte{1, 0, 4, 0})
	for i := 0; i < maxClientHelloRecords+10; i++ {
		input = append(input, helloRecord([]byte{0})...)
	}
	conn := &flightReader{Reader: bytes.NewReader(input)}
	raw, _, err := readClientHelloFlight(conn, time.Second)
	if err == nil || len(raw) >= len(input) || len(conn.deadlines) != 2 {
		t.Fatal("fragment limit not enforced")
	}
}

func TestClientHelloParserRejectsMalformedVectors(t *testing.T) {
	for _, input := range [][]byte{
		parserHello([]byte{0x13}, nil), parserHello(nil, nil),
		parserHello([]byte{0x13, 1}, []byte{0, 10, 0, 0, 0, 10, 0, 0}),
		parserHello([]byte{0x13, 1}, []byte{0, 10, 0, 2, 0}),
	} {
		if _, _, _, _, _, _, err := parseClientHelloInfo(input); err == nil {
			t.Fatal("malformed vector accepted")
		}
	}
	if _, _, _, _, _, _, err := parseClientHelloInfo(parserHello([]byte{0x13, 1}, nil)); err != nil {
		t.Fatal(err)
	}
}

func FuzzClientHelloParser(f *testing.F) {
	f.Add(parserHello([]byte{0x13, 1}, nil))
	f.Add(parserHello([]byte{0x13}, nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _, _, _ = parseClientHelloInfo(data)
		conn := &flightReader{Reader: bytes.NewReader(data)}
		raw, _, _ := readClientHelloFlight(conn, time.Second)
		if !bytes.HasPrefix(data, raw) {
			t.Fatal("consumed bytes were changed")
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatal(err)
		}
	})
}
