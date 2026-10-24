package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDNSExchangeDiagnostics(t *testing.T) {
	query := make([]byte, 12)
	query[0] = 0x12
	query[1] = 0x34
	for _, tc := range []struct {
		name, stage string
		response    []byte
	}{
		{"short length", "response length", []byte{0, 1, 0}},
		{"short body", "response body", []byte{0, 12, 0}},
		{"wrong transaction", "response validation", append([]byte{0, 12}, make([]byte, 12)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := net.Pipe()
			go func() {
				defer second.Close()
				buffer := make([]byte, 14)
				_, _ = io.ReadFull(second, buffer)
				_, _ = second.Write(tc.response)
			}()
			_, err := exchangeDNS(query, "1.1.1.1:53", func(string, string) (net.Conn, error) { return first, nil }, time.Second)
			var diagnostic *dnsExchangeError
			if !errors.As(err, &diagnostic) || diagnostic.Stage != tc.stage {
				t.Fatalf("expected %s: %v", tc.stage, err)
			}
		})
	}
	_, err := exchangeDNS(query, "1.1.1.1:53", func(string, string) (net.Conn, error) { return nil, errors.New("connect failed") }, time.Second)
	if err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatal(err)
	}
}

func TestDNSExchangeSuccessAndTimeout(t *testing.T) {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query, 77)
	first, second := net.Pipe()
	go func() {
		defer second.Close()
		buffer := make([]byte, 14)
		_, _ = io.ReadFull(second, buffer)
		buffer[4] |= 0x80
		_, _ = second.Write(buffer)
	}()
	response, err := exchangeDNS(query, "1.1.1.1:53", func(string, string) (net.Conn, error) { return first, nil }, time.Second)
	if err != nil || len(response) != 12 || response[2]&0x80 == 0 {
		t.Fatal(err)
	}
	first, second = net.Pipe()
	defer second.Close()
	_, err = exchangeDNS(query, "1.1.1.1:53", func(string, string) (net.Conn, error) { return first, nil }, 20*time.Millisecond)
	if err == nil {
		t.Fatal("blocked DNS operation did not time out")
	}
}

func TestDNSErrorsVisibleAtErrorLevelWithoutQueryPayload(t *testing.T) {
	previous := log.Writer()
	defer log.SetOutput(previous)
	coreLogMu.Lock()
	oldLevel := coreLogLevel
	coreLogLevel = "error"
	coreLogMu.Unlock()
	defer func() { coreLogMu.Lock(); coreLogLevel = oldLevel; coreLogMu.Unlock() }()
	dnsLogState.Lock()
	dnsLogState.last = time.Time{}
	dnsLogState.suppressed = 0
	dnsLogState.Unlock()
	var buffer bytes.Buffer
	log.SetOutput(&coreLogFilterWriter{underlying: &buffer})
	reportDNSError("1.1.1.1:53", &dnsExchangeError{"response length", io.EOF})
	if !strings.Contains(buffer.String(), "[ERROR] [DNS]") || !strings.Contains(buffer.String(), "response length") {
		t.Fatal("DNS failure disappeared at error log level")
	}
	reportDNSError("1.1.1.1:53", io.EOF)
	if strings.Count(buffer.String(), "[DNS]") != 1 {
		t.Fatal("repeated DNS errors were not limited")
	}
}

func TestDNSEndpointIPv6(t *testing.T) {
	for _, value := range []string{"2606:4700:4700::1111", "[2606:4700:4700::1111]:53"} {
		endpoint, err := dnsEndpoint(value)
		if err != nil || endpoint != "[2606:4700:4700::1111]:53" {
			t.Fatal(endpoint, err)
		}
	}
}
