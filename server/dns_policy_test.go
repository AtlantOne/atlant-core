package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func policyDNSReply(t testing.TB, qtype dnsmessage.Type) []byte {
	t.Helper()
	name, err := dnsmessage.NewName("www.youtube.com.")
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, Response: true, RecursionDesired: true, RecursionAvailable: true, AuthenticData: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	if qtype == dnsmessage.TypeA {
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{142, 250, 1, 1}}}}
	} else if qtype == dnsmessage.TypeAAAA {
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x48, 0x60}}}}
	} else {
		msg.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: qtype, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.UnknownResource{Type: qtype, Data: []byte{0, 1, 0, 0, 6, 0, 16, 0x20, 1, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}}}
	}
	packet, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestDNSIPv4PolicyPreservesAAndSuppressesIPv6Discovery(t *testing.T) {
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.Type(64), dnsmessage.Type(65)} {
		t.Run(qtype.String(), func(t *testing.T) {
			packet := policyDNSReply(t, qtype)
			original := append([]byte(nil), packet...)
			response := ipv4DNSResponse(packet)
			if !bytes.Equal(packet, original) {
				t.Fatal("mutated upstream read buffer")
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(response); err != nil {
				t.Fatal(err)
			}
			if msg.ID != 0x1234 || !msg.Response || !msg.RecursionDesired || !msg.RecursionAvailable || len(msg.Questions) != 1 || msg.Questions[0].Type != qtype {
				t.Fatal("lost DNS identity/question/flags")
			}
			if qtype == dnsmessage.TypeA {
				if !bytes.Equal(packet, response) {
					t.Fatal("modified A response or DNSSEC flags")
				}
			} else if len(msg.Answers) != 0 || len(msg.Authorities) != 0 || len(msg.Additionals) != 0 || msg.AuthenticData || msg.Authoritative || msg.Truncated || msg.RCode != dnsmessage.RCodeSuccess {
				t.Fatal("invalid policy NODATA response")
			}
		})
	}
}

func TestDNSIPv4PolicyDoesNotRewriteInvalidOrNegativePackets(t *testing.T) {
	valid := policyDNSReply(t, dnsmessage.TypeAAAA)
	nx := append([]byte(nil), valid...)
	nx[3] = (nx[3] & 0xf0) | 3
	query := append([]byte(nil), valid...)
	query[2] &= 0x7f
	for _, packet := range [][]byte{nil, {1, 2}, valid[:len(valid)-1], nx, query} {
		if got := ipv4DNSResponse(packet); !bytes.Equal(got, packet) {
			t.Fatal("rewrote invalid, negative, or non-response input")
		}
	}
}

func TestDNSPolicyOptInAndPortScope(t *testing.T) {
	old := cfg
	defer func() { cfg = old }()
	cfg = &Config{}
	packet := policyDNSReply(t, dnsmessage.TypeAAAA)
	if !bytes.Equal(dnsUDPResponse("1.1.1.1:53", packet), packet) {
		t.Fatal("policy enabled by default")
	}
	configMu.Lock()
	cfg.DNSIPv4Only = true
	configMu.Unlock()
	for _, destination := range []string{"1.1.1.1:443", "video.example:853", "invalid"} {
		if !bytes.Equal(dnsUDPResponse(destination, packet), packet) {
			t.Fatal("parsed non-DNS traffic")
		}
	}
	if bytes.Equal(dnsUDPResponse("1.1.1.1:53", packet), packet) {
		t.Fatal("enabled DNS policy ignored")
	}
}

func TestDNSPolicyTCPFramingPartialReadsAndMultipleMessages(t *testing.T) {
	upstream, peer := net.Pipe()
	defer upstream.Close()
	defer peer.Close()
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	conn := &dnsPolicyTCPConn{Conn: upstream}
	packets := [][]byte{policyDNSReply(t, dnsmessage.TypeAAAA), policyDNSReply(t, dnsmessage.TypeA), policyDNSReply(t, dnsmessage.Type(65))}
	done := make(chan error, 1)
	go func() {
		for _, packet := range packets {
			frame := make([]byte, 2+len(packet))
			binary.BigEndian.PutUint16(frame, uint16(len(packet)))
			copy(frame[2:], packet)
			for _, b := range frame {
				if _, err := peer.Write([]byte{b}); err != nil {
					done <- err
					return
				}
			}
		}
		done <- nil
	}()
	for _, packet := range packets {
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, int(binary.BigEndian.Uint16(header[:])))
		for i := range got {
			if _, err := io.ReadFull(conn, got[i:i+1]); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, ipv4DNSResponse(packet)) {
			t.Fatal("TCP frame corrupted")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDNSPolicyTCPCloseUnblocksRead(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn := &dnsPolicyTCPConn{Conn: left}
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 100)); done <- err }()
	_ = conn.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("read leaked on close")
	}
}

func FuzzIPv4DNSResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add(policyDNSReply(f, dnsmessage.TypeAAAA))
	f.Add(policyDNSReply(f, dnsmessage.Type(65)))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65535 {
			return
		}
		original := append([]byte(nil), packet...)
		response := ipv4DNSResponse(packet)
		if !bytes.Equal(packet, original) {
			t.Fatal("mutated input")
		}
		if len(response) > 65535 {
			t.Fatal("DNS output exceeds TCP frame size")
		}
		if !bytes.Equal(response, packet) {
			var msg dnsmessage.Message
			if err := msg.Unpack(response); err != nil || msg.AuthenticData || len(msg.Answers) != 0 {
				t.Fatal("invalid synthetic response")
			}
		}
	})
}
