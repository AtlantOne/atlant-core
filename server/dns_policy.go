package main

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// This is an explicit DNS discovery policy, NOT an IPv6 route, translator or
// leak-prevention mechanism. It cannot fix IPv6 literals or encrypted DNS.
// It is disabled by default, and preserves A responses byte-for-byte.
func dnsIPv4PolicyEnabled(destination string) bool {
	_, port, err := net.SplitHostPort(destination)
	return err == nil && port == "53" && cfg != nil && cfg.Runtime().DNSIPv4Only
}

func ipv4DNSResponse(packet []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		return packet
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return packet
	}
	// HTTPS/SVCB may advertise IPv6 hints even if AAAA is suppressed. Returning
	// NODATA for these discovery queries leaves ordinary A lookup available.
	qtype := questions[0].Type
	if qtype != dnsmessage.TypeAAAA && qtype != dnsmessage.Type(64) && qtype != dnsmessage.Type(65) {
		return packet
	}
	// Validate the complete original message before replacing it. No original
	// opaque/compressed RR bodies are repacked; DNS compression pointers cannot
	// accidentally become invalid. Never claim synthesized data is DNSSEC-valid.
	var original dnsmessage.Message
	if err := original.Unpack(packet); err != nil {
		return packet
	}
	header.Authoritative = false
	header.AuthenticData = false
	header.Truncated = false
	response, err := (&dnsmessage.Message{Header: header, Questions: questions}).Pack()
	if err != nil {
		return packet
	}
	return response
}

// Called only for replies from an upstream socket already pinned to a safe
// DNS destination. Non-DNS UDP packets never enter the DNS parser.
func dnsUDPResponse(destination string, packet []byte) []byte {
	if !dnsIPv4PolicyEnabled(destination) {
		return packet
	}
	return ipv4DNSResponse(packet)
}

// DNS-over-TCP has independent 2-byte framing. Buffer exactly one upstream
// message, filter it and preserve partial Read semantics for io.Copy callers.
// Close/deadlines go directly to the underlying socket and unblock a Read.
type dnsPolicyTCPConn struct {
	net.Conn
	mu      sync.Mutex
	pending []byte
}

func (c *dnsPolicyTCPConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		var length [2]byte
		if _, err := io.ReadFull(c.Conn, length[:]); err != nil {
			return 0, err
		}
		packet := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(c.Conn, packet); err != nil {
			return 0, err
		}
		packet = ipv4DNSResponse(packet)
		c.pending = make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(c.pending[:2], uint16(len(packet)))
		copy(c.pending[2:], packet)
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *dnsPolicyTCPConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
