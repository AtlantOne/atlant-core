package wire

import (
	"bytes"
	"encoding/binary"
	"github.com/quic-go/quic-go"
	"testing"
	"time"
)

func TestTunnelDatagramFragmentsBothDirections(t *testing.T) {
	for _, offset := range []int{4, 8} {
		for _, n := range []int{32, 1300, 65507} {
			packet := make([]byte, offset+2+12+n)
			binary.BigEndian.PutUint16(packet[offset:], 12)
			copy(packet[offset+2:], "example:1234")
			for i := offset + 14; i < len(packet); i++ {
				packet[i] = byte(i)
			}
			var frames [][]byte
			err := SendTunnelDatagram(packet, offset, func(p []byte) error {
				if len(p) > 1150 {
					return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
				}
				frames = append(frames, append([]byte(nil), p...))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var assembler DatagramAssembler
			var got []byte
			for i := len(frames) - 1; i >= 0; i-- {
				p, ready := assembler.Decode(frames[i], offset, time.Now())
				if ready {
					got = p
				}
				if i > 0 && len(frames) > 1 {
					if _, ready = assembler.Decode(frames[i], offset, time.Now()); ready {
						t.Fatal("Duplicate fragment completed packet")
					}
				}
			}
			if !bytes.Equal(packet, got) {
				t.Fatalf("offset %d payload %d reassembly mismatch", offset, n)
			}
			if assembler.bytes != 0 || len(assembler.packets) != 0 {
				t.Fatal("Completed assembly retained memory")
			}
		}
	}
}

func TestTunnelDatagramAssemblyExpiresAndIsBounded(t *testing.T) {
	packet := make([]byte, 5000)
	binary.BigEndian.PutUint16(packet[8:], 12)
	var frames [][]byte
	SendTunnelDatagram(packet, 8, func(p []byte) error {
		if len(p) > 1150 {
			return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
		}
		frames = append(frames, append([]byte(nil), p...))
		return nil
	})
	var assembler DatagramAssembler
	now := time.Now()
	for i := 0; i < 300; i++ {
		p := append([]byte(nil), frames[0]...)
		binary.BigEndian.PutUint64(p[10:], uint64(i))
		if _, ok := assembler.Decode(p, 8, now); ok {
			t.Fatal("Incomplete packet accepted")
		}
	}
	if len(assembler.packets) > 128 || assembler.bytes > 8*1024*1024 {
		t.Fatal("Assembly bounds exceeded")
	}
	assembler.Decode(frames[1], 8, now.Add(4*time.Second))
	if len(assembler.packets) != 1 {
		t.Fatal("Expired fragments retained")
	}
	bad := append([]byte(nil), frames[0]...)
	binary.BigEndian.PutUint32(bad[18:], 0xffffffff)
	if _, ok := assembler.Decode(bad, 8, now); ok {
		t.Fatal("Invalid total accepted")
	}
}
