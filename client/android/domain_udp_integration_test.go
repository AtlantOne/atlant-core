//go:build android || (linux && atlanttest)

package atlant

import (
	"atlant.local/protocol/quicreality"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type rejectDirectProtector struct{ calls atomic.Int32 }

func (p *rejectDirectProtector) Protect(int) bool { p.calls.Add(1); return false }

func TestDirectUDPFailureDoesNotOverrideBypass(t *testing.T) {
	SetRouteMode("bypass")
	SetDirectDomains("127.0.0.1")
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	guard := &rejectDirectProtector{}
	SetSocketProtector(guard)
	t.Cleanup(func() { SetRouteMode("all"); SetDirectDomains(""); SetSocketProtector(previous) })
	core, app := net.Pipe()
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleUDPConn(core, &Config{ServerAddr: "127.0.0.1:1", UDPMode: "tcp"}, "127.0.0.1:443")
	}()
	if _, err := app.Write([]byte("not QUIC")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed direct socket unexpectedly retried through VPN")
	}
	if guard.calls.Load() != 1 {
		t.Fatalf("expected only the rejected direct socket, got %d attempts", guard.calls.Load())
	}
}

func captureQUICInitial(t *testing.T, version quic.Version) [][]byte {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := quic.DialAddr(ctx, listener.LocalAddr().String(),
			&tls.Config{ServerName: "www.example.ru", NextProtos: []string{"h3"}},
			&quic.Config{Versions: []quic.Version{version}})
		if conn != nil {
			_ = conn.CloseWithError(0, "test finished")
		}
	}()
	defer func() { cancel(); <-done }()
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	var observer quicreality.Observer
	var packets [][]byte
	buffer := make([]byte, 65535)
	for len(packets) < 8 {
		n, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, bytes.Clone(buffer[:n]))
		if _, err := observer.Feed(buffer[:n]); err == nil {
			return packets
		}
	}
	t.Fatal("could not capture complete client Initial")
	return nil
}

func TestDomainBypassRoutesQUICDirectWithoutFakeDNS(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			packets := captureQUICInitial(t, version)
			SetRouteMode("bypass")
			SetDirectDomains("*.ru")
			previousFakeDNS := IsFakeDnsEnabled()
			SetFakeDnsEnabled(false)
			protectorMu.RLock()
			previousProtector := protector
			protectorMu.RUnlock()
			guard := &noTCPProtector{}
			SetSocketProtector(guard)
			t.Cleanup(func() {
				SetRouteMode("all")
				SetDirectDomains("")
				SetFakeDnsEnabled(previousFakeDNS)
				SetSocketProtector(previousProtector)
			})
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			echoDone := make(chan error, 1)
			go func() {
				_ = echo.SetDeadline(time.Now().Add(3 * time.Second))
				buffer := make([]byte, 65535)
				for _, want := range packets {
					n, from, err := echo.ReadFromUDP(buffer)
					if err != nil {
						echoDone <- err
						return
					}
					if !bytes.Equal(buffer[:n], want) {
						echoDone <- io.ErrUnexpectedEOF
						return
					}
					if _, err := echo.WriteToUDP(buffer[:n], from); err != nil {
						echoDone <- err
						return
					}
				}
				echoDone <- nil
			}()
			core, app := net.Pipe()
			defer app.Close()
			_ = app.SetDeadline(time.Now().Add(3 * time.Second))
			relayDone := make(chan struct{})
			go func() {
				defer close(relayDone)
				// No working VPN endpoint: a reply can only arrive on the direct path.
				handleUDPConn(core, &Config{ServerAddr: "127.0.0.1:1", UDPMode: "tcp"}, echo.LocalAddr().String())
			}()
			for _, packet := range packets {
				if _, err := app.Write(packet); err != nil {
					t.Fatal(err)
				}
			}
			for _, packet := range packets {
				got := make([]byte, len(packet))
				if _, err := io.ReadFull(app, got); err != nil || !bytes.Equal(got, packet) {
					t.Fatal("direct UDP reply missing or changed", err)
				}
			}
			if err := <-echoDone; err != nil {
				t.Fatal(err)
			}
			_ = app.Close()
			select {
			case <-relayDone:
			case <-time.After(time.Second):
				t.Fatal("direct relay did not stop")
			}
			if guard.denied.Load() != 0 {
				t.Fatal("direct domain attempted the VPN TCP transport")
			}
		})
	}
}
