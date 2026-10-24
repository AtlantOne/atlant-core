package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in, using the scoped physical-interface bridge. Never changes
// host routes or starts the desktop TUN; credentials stay in a private file.
func TestPCWireProfiles(t *testing.T) {
	path := os.Getenv("ATLANT_WIRE_CHECK_PROFILE")
	if path == "" {
		t.Skip("set ATLANT_WIRE_CHECK_PROFILE for the scoped PC handshake matrix")
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
		t.Fatal("expected the local bridge and the deployed wire4 profile")
	}
	cfg.BackupServers = nil
	previous := physicalLocalIP
	physicalLocalIP = net.ParseIP("127.0.0.1")
	t.Cleanup(func() { physicalLocalIP = previous })
	for _, profile := range []string{"chrome_120", "chrome", "firefox"} {
		t.Run(profile, func(t *testing.T) {
			current := cfg
			current.Fingerprint = profile
			conn, err := dialRealityConn(&current)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := writeAtlantHeader(conn, "udp", "1.1.1.1:53"); err != nil {
				t.Fatal(err)
			}
			query := []byte{0x41, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
			frame := make([]byte, 2+len(query))
			binary.BigEndian.PutUint16(frame, uint16(len(query)))
			copy(frame[2:], query)
			if err := writeFull(conn, frame); err != nil {
				t.Fatal(err)
			}
			var header [2]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				t.Fatal(err)
			}
			answer := make([]byte, binary.BigEndian.Uint16(header[:]))
			if _, err := io.ReadFull(conn, answer); err != nil {
				t.Fatal(err)
			}
			if len(answer) < 12 || answer[0] != query[0] || answer[1] != query[1] || answer[2]&0x80 == 0 || answer[3]&15 != 0 || binary.BigEndian.Uint16(answer[6:8]) == 0 {
				t.Fatal("invalid DNS response")
			}
		})
	}
}

func TestPCWireQUIC(t *testing.T) {
	path := os.Getenv("ATLANT_WIRE_CHECK_PROFILE")
	if path == "" {
		t.Skip("set ATLANT_WIRE_CHECK_PROFILE for the scoped PC QUIC check")
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
		t.Fatal("expected the local bridge and deployed wire4 profile")
	}
	cfg.BackupServers = nil
	cfg.Fingerprint = "chrome_120"
	previous := physicalLocalIP
	physicalLocalIP = net.ParseIP("127.0.0.1")
	t.Cleanup(func() {
		if quicClientConn != nil {
			_ = quicClientConn.CloseWithError(0, "wire check complete")
		}
		if quicClientTransport != nil {
			_ = quicClientTransport.Close()
		}
		if quicClientPacket != nil {
			_ = quicClientPacket.Close()
		}
		physicalLocalIP = previous
	})
	conn, err := dialQUICStream(&cfg, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	query := []byte{0x41, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeFull(conn, frame); err != nil {
		t.Fatal(err)
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, answer); err != nil {
		t.Fatal(err)
	}
	if len(answer) < 12 || answer[0] != query[0] || answer[1] != query[1] || answer[2]&0x80 == 0 || answer[3]&15 != 0 || binary.BigEndian.Uint16(answer[6:8]) == 0 {
		t.Fatal("invalid DNS response through wire4 QUIC")
	}
}
