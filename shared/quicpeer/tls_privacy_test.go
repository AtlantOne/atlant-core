package quicpeer

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"
)

func TestWire3DisablesSessionIdentifiersWithoutChangingAuthentication(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(4)
	for _, version := range []int{2, 3, 4, 6, 7} {
		config := &tls.Config{ServerName: "example.invalid", NextProtos: []string{"h3"}, ClientSessionCache: cache}
		ConfigureTLSPrivacy(config, version)
		if version >= 3 && (!config.SessionTicketsDisabled || config.ClientSessionCache != nil) {
			t.Fatal("wire3 still accepts reusable tickets")
		}
		if version == 2 && (config.SessionTicketsDisabled || config.ClientSessionCache != cache) {
			t.Fatal("legacy ticket policy changed")
		}
		if config.InsecureSkipVerify || config.ServerName != "example.invalid" || len(config.NextProtos) != 1 || config.NextProtos[0] != "h3" {
			t.Fatal("unrelated TLS verification or protocol changed")
		}
	}
}

func TestWire3TLSDoesNotResumeAcrossConnections(t *testing.T) {
	for _, version := range []int{2, 3} {
		t.Run(map[int]string{2: "legacy", 3: "wire3"}[version], func(t *testing.T) {
			cert := certificate(t)
			roots := x509.NewCertPool()
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots.AddCert(parsed)
			serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
			clientTLS := &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
			ConfigureTLSPrivacy(serverTLS, version)
			ConfigureTLSPrivacy(clientTLS, version)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 2; i++ {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, err = conn.Write([]byte{1})
					_ = conn.Close()
					if err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			for attempt := 0; attempt < 2; attempt++ {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), clientTLS)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var marker [1]byte
				_, err = io.ReadFull(conn, marker[:])
				resumed := conn.ConnectionState().DidResume
				_ = conn.Close()
				if err != nil {
					t.Fatal(err)
				}
				if resumed != (version == 2 && attempt == 1) {
					t.Fatalf("unexpected resumption: version=%d attempt=%d resumed=%v", version, attempt, resumed)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
