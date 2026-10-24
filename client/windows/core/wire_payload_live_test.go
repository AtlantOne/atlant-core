package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Compare data transport independently of DNS, destination websites and TUN.
// The opt-in bridge keeps other VPNs and system routes untouched.
func TestPCWirePayload(t *testing.T) {
	path := os.Getenv("ATLANT_WIRE_CHECK_PROFILE")
	if path == "" {
		t.Skip("explicit live profile required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.ServerAddr, "127.0.0.1:") || cfg.WireVersion != 4 {
		t.Fatal("expected the scoped bridge and wire4")
	}
	cfg.BackupServers = nil
	cfg.Fingerprint = "firefox"
	previous := physicalLocalIP
	physicalLocalIP = net.ParseIP("127.0.0.1")
	t.Cleanup(func() {
		if quicClientConn != nil {
			_ = quicClientConn.CloseWithError(0, "payload check complete")
		}
		if quicClientTransport != nil {
			_ = quicClientTransport.Close()
		}
		if quicClientPacket != nil {
			_ = quicClientPacket.Close()
		}
		physicalLocalIP = previous
	})
	for _, transport := range []string{"tcp", "quic"} {
		t.Run(transport, func(t *testing.T) {
			started := time.Now()
			var conn net.Conn
			var err error
			if transport == "quic" {
				conn, err = dialQUICStream(&cfg, "tcp", "speedtest:80")
			} else {
				conn, err = dialRealityConn(&cfg)
				if err == nil {
					err = writeAtlantHeader(conn, "tcp", "speedtest:80")
				}
			}
			if conn != nil {
				defer conn.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(25 * time.Second))
			reader := bufio.NewReader(conn)
			const upload = 256 * 1024
			if _, err := fmt.Fprintf(conn, "UPLOAD %d\n", upload); err != nil {
				t.Fatal(err)
			}
			line, err := reader.ReadString('\n')
			if err != nil || line != fmt.Sprintf("START %d\n", upload) {
				t.Fatalf("upload start: %q %v", line, err)
			}
			if err := writeFull(conn, bytes.Repeat([]byte{0x5a}, upload)); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, fmt.Sprintf("DONE %d ", upload)) {
				t.Fatalf("upload complete: %q %v", line, err)
			}
			const download = 1024 * 1024
			if _, err := fmt.Fprintf(conn, "DOWNLOAD %d\n", download); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadString('\n')
			if err != nil || line != fmt.Sprintf("START %d\n", download) {
				t.Fatalf("download start: %q %v", line, err)
			}
			payload := make([]byte, download)
			n, err := io.ReadFull(reader, payload)
			if err != nil {
				t.Fatalf("download stopped at %d bytes: %v", n, err)
			}
			for i := 65536; i < download; i += 65536 {
				if !bytes.Equal(payload[:65536], payload[i:i+65536]) {
					t.Fatal("download bytes changed across records")
				}
			}
			if _, err := io.WriteString(conn, "PING after-transfer\n"); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadString('\n')
			if err != nil || line != "PONG after-transfer\n" {
				t.Fatalf("post-transfer ping: %q %v", line, err)
			}
			t.Logf("upload=%d download=%d total=%v", upload, download, time.Since(started).Round(time.Millisecond))
			// Exercise real end-to-end TLS and HTTP, not just a successful VPN
			// handshake. These bounded requests are controls, not site-specific fixes.
			for _, host := range []string{"www.cloudflare.com", "www.google.com", "www.wikipedia.org"} {
				t.Run(host, func(t *testing.T) {
					started := time.Now()
					var upstream net.Conn
					var err error
					if transport == "quic" {
						upstream, err = dialQUICStream(&cfg, "tcp", net.JoinHostPort(host, "443"))
					} else {
						upstream, err = dialRealityConn(&cfg)
						if err == nil {
							err = writeAtlantHeader(upstream, "tcp", net.JoinHostPort(host, "443"))
						}
					}
					if upstream != nil {
						defer upstream.Close()
					}
					if err != nil {
						t.Fatal(err)
					}
					_ = upstream.SetDeadline(time.Now().Add(12 * time.Second))
					secure := tls.Client(upstream, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
					defer secure.Close()
					if err := secure.Handshake(); err != nil {
						t.Fatalf("origin TLS: %v", err)
					}
					request, _ := http.NewRequest(http.MethodGet, "https://"+host+"/robots.txt", nil)
					request.Close = true
					if err := request.Write(secure); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(secure), request)
					if err != nil {
						t.Fatalf("origin headers: %v", err)
					}
					defer response.Body.Close()
					n, err := io.Copy(io.Discard, io.LimitReader(response.Body, 128*1024))
					if err != nil {
						t.Fatalf("origin body: %v", err)
					}
					t.Logf("status=%d bytes=%d elapsed=%v", response.StatusCode, n, time.Since(started).Round(time.Millisecond))
				})
			}
		})
	}
}
