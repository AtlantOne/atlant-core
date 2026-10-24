package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type dnsExchangeError struct {
	Stage string
	Err   error
}

func (e *dnsExchangeError) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Err) }
func (e *dnsExchangeError) Unwrap() error { return e.Err }

// Do not log query names or payloads. Bound repeated failures while preserving
// the first diagnostic at the error-only logging level.
var dnsLogState struct {
	sync.Mutex
	last       time.Time
	suppressed uint64
}

func reportDNSError(target string, err error) {
	dnsLogState.Lock()
	defer dnsLogState.Unlock()
	if time.Since(dnsLogState.last) < time.Second {
		dnsLogState.suppressed++
		return
	}
	log.Printf("[ERROR] [DNS] upstream=%q failed: %v (suppressed=%d)", target, err, dnsLogState.suppressed)
	dnsLogState.last = time.Now()
	dnsLogState.suppressed = 0
}

func dnsEndpoint(value string) (string, error) {
	if value == "" {
		value = "1.1.1.1"
	}
	if ip := net.ParseIP(value); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || net.ParseIP(host) == nil || port != "53" {
		return "", fmt.Errorf("DNS must be an IP address with optional port 53")
	}
	return net.JoinHostPort(host, port), nil
}

func exchangeDNS(query []byte, target string, dial func(string, string) (net.Conn, error), timeout time.Duration) ([]byte, error) {
	fail := func(stage string, err error) ([]byte, error) { return nil, &dnsExchangeError{Stage: stage, Err: err} }
	if len(query) < 12 || len(query) > 65535 {
		return fail("query", fmt.Errorf("invalid DNS message size"))
	}
	conn, err := dial("udp", target)
	if err != nil {
		return fail("connect", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fail("deadline", err)
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeFull(conn, frame); err != nil {
		return fail("send", err)
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fail("response length", err)
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 {
		return fail("response length", fmt.Errorf("DNS response shorter than header"))
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fail("response body", err)
	}
	if binary.BigEndian.Uint16(response) != binary.BigEndian.Uint16(query) || response[2]&0x80 == 0 {
		return fail("response validation", fmt.Errorf("unexpected transaction ID or QR flag"))
	}
	return response, nil
}
