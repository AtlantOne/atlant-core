//go:build android || (linux && atlanttest)

package atlant

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestLivePayloadPaths(t *testing.T) {
	cfg := liveConfig(t)
	for _, mode := range []string{"tcp", "quic"} {
		t.Run(mode, func(t *testing.T) {
			dial := func(target string) (net.Conn, error) {
				if mode == "quic" {
					return dialQUICStream(cfg, "tcp", target)
				}
				return dialRealityDirect(cfg, "tcp", target)
			}
			started := time.Now()
			conn, err := dial("speedtest:80")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			reader := bufio.NewReader(conn)
			if _, err := io.WriteString(conn, "UPLOAD 65536\n"); err != nil {
				t.Fatal(err)
			}
			line, err := reader.ReadString('\n')
			if err != nil || line != "START 65536\n" {
				t.Fatalf("upload start: %q %v", line, err)
			}
			if err := writeFull(conn, bytes.Repeat([]byte{0x5a}, 65536)); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadString('\n')
			var received int
			if _, scanErr := fmt.Sscanf(line, "DONE %d", &received); err != nil || scanErr != nil || received != 65536 {
				t.Fatalf("upload response: %q %v", line, err)
			}
			if _, err := io.WriteString(conn, "DOWNLOAD 262144\n"); err != nil {
				t.Fatal(err)
			}
			line, err = reader.ReadString('\n')
			if err != nil || line != "START 262144\n" {
				t.Fatalf("download start: %q %v", line, err)
			}
			payload := make([]byte, 262144)
			if n, err := io.ReadFull(reader, payload); err != nil {
				t.Fatalf("download stopped at %d: %v", n, err)
			}
			for offset := 65536; offset < len(payload); offset += 65536 {
				if !bytes.Equal(payload[:65536], payload[offset:offset+65536]) {
					t.Fatal("payload changed across TLS records")
				}
			}
			t.Logf("bulk transfer elapsed=%v", time.Since(started).Round(time.Millisecond))
			for _, host := range []string{"www.cloudflare.com", "www.google.com"} {
				t.Run(host, func(t *testing.T) {
					started := time.Now()
					upstream, err := dial(net.JoinHostPort(host, "443"))
					if err != nil {
						t.Fatal(err)
					}
					defer upstream.Close()
					_ = upstream.SetDeadline(time.Now().Add(8 * time.Second))
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
						t.Fatal(err)
					}
					defer response.Body.Close()
					n, err := io.Copy(io.Discard, io.LimitReader(response.Body, 128*1024))
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("status=%d bytes=%d elapsed=%v", response.StatusCode, n, time.Since(started).Round(time.Millisecond))
				})
			}
		})
	}
}
