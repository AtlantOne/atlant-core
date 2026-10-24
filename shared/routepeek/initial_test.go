package routepeek

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func helloForTest(name string) []byte {
	body := make([]byte, 35)
	body[0] = 3
	body[1] = 3
	body = append(body, 0, 2, 0x13, 1, 1, 0)
	sni := []byte{0, byte(3 + len(name)), 0, 0, byte(len(name))}
	sni = append(sni, []byte(name)...)
	ext := []byte{0, 0, 0, byte(len(sni))}
	ext = append(ext, sni...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return recordForTest(hs)
}

func recordForTest(payload []byte) []byte {
	h := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(h[3:], uint16(len(payload)))
	return append(h, payload...)
}

func TestReadPreservesSegmentedHello(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	want := helloForTest("private.example")
	go func() { defer b.Close(); b.Write(want[:9]); time.Sleep(10 * time.Millisecond); b.Write(want[9:]) }()
	got := Read(a, time.Second)
	if !bytes.Equal(got, want) || ServerName(got) != "private.example" {
		t.Fatalf("prefix lost or name not collected")
	}
}

func TestHelloAcrossTLSRecords(t *testing.T) {
	hello := helloForTest("example.com")[5:]
	data := append(recordForTest(hello[:13]), recordForTest(hello[13:])...)
	if ServerName(data) != "example.com" {
		t.Fatal("fragmented TLS name missing")
	}
}

func TestIncompleteHasNoTrustedName(t *testing.T) {
	hello := helloForTest("example.com")
	for n := 0; n < len(hello); n++ {
		if ServerName(hello[:n]) != "" {
			t.Fatal("accepted incomplete hello")
		}
	}
}

func TestHTTPRequiresCompleteUnambiguousHeaders(t *testing.T) {
	if HTTPHost([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")) != "example.com" {
		t.Fatal("missing name")
	}
	for _, s := range []string{"GET / HTTP/1.1\r\nHost: example.com", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"} {
		if HTTPHost([]byte(s)) != "" {
			t.Fatal("accepted ambiguous or partial host")
		}
	}
}
