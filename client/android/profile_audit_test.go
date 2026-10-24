//go:build android || (linux && atlanttest)

package atlant

import (
	"atlant.local/protocol/tlsaudit"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	u "github.com/refraction-networking/utls"
)

func captureStockProfile(t *testing.T, id u.ClientHelloID) []byte {
	t.Helper()
	spec, err := u.UTLSIdToSpec(id)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	conn := u.UClient(client, &u.Config{ServerName: "example.com"}, u.HelloCustom)
	if err := conn.ApplyPreset(&spec); err != nil {
		client.Close()
		server.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = conn.Handshake() }()
	defer func() {
		client.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("uTLS capture goroutine leaked")
		}
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	var records, payload []byte
	for len(records) < 128<<10 {
		var header [5]byte
		if _, err := io.ReadFull(server, header[:]); err != nil {
			t.Fatal(err)
		}
		n := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 0x16 || n < 1 || n > 16384 {
			t.Fatal("unexpected stock ClientHello record")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(server, body); err != nil {
			t.Fatal(err)
		}
		records = append(records, header[:]...)
		records = append(records, body...)
		payload = append(payload, body...)
		if len(payload) >= 4 && len(payload) >= 4+(int(payload[1])<<16|int(payload[2])<<8|int(payload[3])) {
			return records
		}
	}
	t.Fatal("oversized stock ClientHello")
	return nil
}

func TestDefaultFingerprintUsesFirefoxWithoutOverridingExplicitChrome(t *testing.T) {
	previous := GetFingerprint()
	t.Cleanup(func() { SetFingerprint(previous) })
	SetFingerprint("")
	if GetFingerprint() != "firefox" {
		t.Fatal("empty profile must select Firefox")
	}
	SetFingerprint("chrome")
	if GetFingerprint() != "chrome" {
		t.Fatal("explicit Chrome must be preserved")
	}
}

func TestRealityMatchesUnmodifiedUTLSProfile(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   u.ClientHelloID
	}{
		{"chrome", u.HelloChrome_133}, {"chrome_120", u.HelloChrome_120},
		{"chrome_144", u.HelloChrome_133}, {"chrome_133", u.HelloChrome_133}, {"chrome_auto", u.HelloChrome_133}, {"", u.HelloFirefox_120},
		{"firefox", u.HelloFirefox_120}, {"safari", u.HelloSafari_16_0},
		{"ios", u.HelloIOS_14}, {"edge", u.HelloEdge_106},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline, err := tlsaudit.Summarize(captureStockProfile(t, tc.id))
			if err != nil {
				t.Fatal(err)
			}
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			var token [32]byte
			_, _ = rand.Read(token[:])
			hello, err := buildClientHelloWithUTLS("example.com", token[:], key.PublicKey().Bytes(), tc.name)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := tlsaudit.Summarize(hello)
			if err != nil {
				t.Fatal(err)
			}
			if baseline.StructuralKey() != actual.StructuralKey() {
				t.Fatalf("REALITY changed profile structure\nstock: %s\nactual: %s", baseline.StructuralKey(), actual.StructuralKey())
			}
		})
	}
}

func TestRealityDoesNotInventKeyShareForTLS12Profile(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := buildClientHelloWithUTLS("example.com", make([]byte, 32), key.PublicKey().Bytes(), "android"); err == nil {
		t.Fatal("TLS1.2 OkHttp profile silently gained a non-native key_share extension")
	}
	if _, err := buildClientHelloWithUTLS("example.com", make([]byte, 32), key.PublicKey().Bytes(), "not-a-profile"); err == nil {
		t.Fatal("unknown profile silently replaced with Chrome")
	}
}
