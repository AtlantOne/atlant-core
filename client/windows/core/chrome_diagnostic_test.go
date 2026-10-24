package main

import (
	"atlant.local/protocol/realityauth"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestChrome144AdmissionLayout(t *testing.T) {
	path := os.Getenv("ATLANT_CHROME_DIAGNOSTIC_PROFILE")
	if path == "" {
		t.Skip("external diagnostic required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.WireVersion != 7 {
		t.Fatal("wire7 required")
	}
	secret, err := hex.DecodeString(cfg.PBK)
	if err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(cfg.ServerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		hello, err := buildClientHelloWithUTLS(cfg.SNI, make([]byte, 32), key.PublicKey().Bytes(), "chrome")
		if err != nil {
			t.Fatal(err)
		}
		if err = realityauth.BindHelloVersion(7, hello, cfg.User, secret, key, public, time.Now()); err != nil {
			t.Fatal(err)
		}
		offset := 43
		offset += 1 + int(hello[offset])
		offset += 2 + int(binary.BigEndian.Uint16(hello[offset:]))
		offset += 1 + int(hello[offset])
		offset += 2
		sniOffset, shareOffset := -1, -1
		for offset+4 <= len(hello) {
			kind, size := binary.BigEndian.Uint16(hello[offset:]), int(binary.BigEndian.Uint16(hello[offset+2:]))
			if kind == 0 {
				sniOffset = offset
			}
			if kind == 51 {
				shareOffset = offset
			}
			offset += 4 + size
		}
		conn, err := net.DialTimeout("tcp", cfg.ServerAddr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		if os.Getenv("ATLANT_TEST_FRAGMENT_HELLO") == "1" {
			for payload := hello[5:]; len(payload) > 0; {
				n := len(payload)
				if n > 1024 {
					n = 1024
				}
				record := append([]byte(nil), hello[:5]...)
				binary.BigEndian.PutUint16(record[3:5], uint16(n))
				record = append(record, payload[:n]...)
				if err = writeFull(conn, record); err != nil {
					break
				}
				payload = payload[n:]
			}
		} else {
			err = writeFull(conn, hello)
		}
		var header [5]byte
		if err == nil {
			_, err = io.ReadFull(conn, header[:])
		}
		conn.Close()
		t.Logf("layout=%d bytes=%d sni=%d key_share=%d server_hello=%t error=%v", i, len(hello), sniOffset, shareOffset, err == nil && header[0] == 22, err)
		if err != nil {
			t.Errorf("Chrome admission timed out, layout %d", i)
		}
	}
}

// Opt-in diagnostic using the physical-interface loopback bridge. No TUN or
// host routing changes; the private profile is never printed.
func TestChrome144DiagnosticMatrix(t *testing.T) {
	path := os.Getenv("ATLANT_CHROME_DIAGNOSTIC_PROFILE")
	if path == "" {
		t.Skip("scoped external handshake diagnostic required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.WireVersion != 7 {
		t.Fatal("wire7 profile required")
	}
	previous := physicalLocalIP
	physicalLocalIP = nil
	t.Cleanup(func() { physicalLocalIP = previous })
	for _, fingerprint := range []string{"firefox", "chrome_120", "chrome"} {
		for _, transport := range []string{"reality", "xhttp"} {
			t.Run(fingerprint+"/"+transport, func(t *testing.T) {
				current := cfg
				current.Fingerprint = fingerprint
				var conn io.ReadWriteCloser
				if transport == "xhttp" {
					c, e := dialXHTTPStream(&current, "udp", "1.1.1.1:53")
					err = e
					if e == nil {
						_ = c.SetDeadline(time.Now().Add(12 * time.Second))
						conn = c
					}
				} else {
					c, e := dialRealityConn(&current)
					if e == nil {
						e = writeAtlantHeader(c, "udp", "1.1.1.1:53")
						if e != nil {
							c.Close()
						}
					}
					err = e
					if e == nil {
						_ = c.SetDeadline(time.Now().Add(12 * time.Second))
						conn = c
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				query := []byte{0x41, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
				frame := make([]byte, 2+len(query))
				binary.BigEndian.PutUint16(frame, uint16(len(query)))
				copy(frame[2:], query)
				if _, err = conn.Write(frame); err != nil {
					t.Fatal(err)
				}
				var size [2]byte
				if _, err = io.ReadFull(conn, size[:]); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err = io.ReadFull(conn, response); err != nil {
					t.Fatal(err)
				}
				if len(response) < 12 || response[0] != query[0] || response[1] != query[1] || response[2]&128 == 0 || response[3]&15 != 0 {
					t.Fatal("invalid DNS response")
				}
			})
		}
	}
}
