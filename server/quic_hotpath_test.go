package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

type packetDiscard struct{}

func (*packetDiscard) ReadFrom([]byte) (int, net.Addr, error)    { return 0, nil, net.ErrClosed }
func (*packetDiscard) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*packetDiscard) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (*packetDiscard) Close() error                     { return nil }
func (*packetDiscard) SetDeadline(time.Time) error      { return nil }
func (*packetDiscard) SetReadDeadline(time.Time) error  { return nil }
func (*packetDiscard) SetWriteDeadline(time.Time) error { return nil }

type legacyDemuxWriter struct{ *DemuxPacketConn }

func (d *legacyDemuxWriter) WriteTo(p []byte, addr net.Addr) (int, error) {
	now := time.Now()
	addrStr := addr.String()
	d.authClients.Set(addrStr, now)
	authUser := getBoundAuthenticatedUser(addrStr)

	// Intercept server's Source Connection ID in Handshake packets
	if len(p) > 6 && (p[0]&0x80) != 0 {
		dcil := int(p[5])
		scilOffset := 6 + dcil
		if len(p) > scilOffset {
			scil := int(p[scilOffset])
			if scil > 0 && len(p) >= scilOffset+1+scil {
				serverSCID := string(p[scilOffset+1 : scilOffset+1+scil])
				d.authCIDs.Set(serverSCID, now)
				if authUser != "" {
					bindAuthenticatedUser(serverSCID, authUser)
				}
			}
		}
	}
	if dcid := extractDCID(p); dcid != "" {
		d.authCIDs.Set(dcid, now)
		if authUser != "" {
			bindAuthenticatedUser(dcid, authUser)
		}
	}
	return d.rawConn.WriteTo(p, addr)
}

func BenchmarkDemuxShortHeaderWrite(b *testing.B) {
	for _, legacy := range []bool{true, false} {
		name := "optimized"
		if legacy {
			name = "legacy"
		}
		b.Run(name, func(b *testing.B) {
			d := &DemuxPacketConn{rawConn: &packetDiscard{}, authClients: NewShardedAuthMap(), authCIDs: NewShardedAuthMap()}
			addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 54321}
			bindAuthenticatedUser(addr.String(), "bench-user")
			packet := bytes.Repeat([]byte{7}, 1200)
			packet[0] = 0x40
			var write func([]byte, net.Addr) (int, error) = d.WriteTo
			if legacy {
				write = (&legacyDemuxWriter{d}).WriteTo
			}
			for range 10 {
				_, _ = write(packet, addr)
			}
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := write(packet, addr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
func TestQUICReplayCacheFailsClosedAtCapacity(t *testing.T) {
	usedDCIDsMu.Lock()
	saved := usedDCIDs
	usedDCIDs = make(map[string]time.Time, maxQUICReplayEntries)
	for i := 0; i < maxQUICReplayEntries; i++ {
		usedDCIDs[fmt.Sprint(i)] = time.Now()
	}
	usedDCIDsMu.Unlock()
	defer func() { usedDCIDsMu.Lock(); usedDCIDs = saved; usedDCIDsMu.Unlock() }()
	if rememberQUICInitial("new", time.Now()) || rememberQUICInitial("1", time.Now()) {
		t.Fatal("full cache admitted new/replayed Initial")
	}
	usedDCIDsMu.Lock()
	n := len(usedDCIDs)
	usedDCIDsMu.Unlock()
	if n != maxQUICReplayEntries {
		t.Fatal("live replay records evicted")
	}
}

func TestReplayCleanupKeepsFutureTimestampAcceptanceWindow(t *testing.T) {
	now := time.Now()
	usedDCIDsMu.Lock()
	saved := usedDCIDs
	usedDCIDs = map[string]time.Time{"still-replayable": now.Add(-4 * time.Minute), "expired": now.Add(-16 * time.Minute)}
	usedDCIDsMu.Unlock()
	defer func() { usedDCIDsMu.Lock(); usedDCIDs = saved; usedDCIDsMu.Unlock() }()
	cleanupQUICReplayCache(now)
	usedDCIDsMu.Lock()
	defer usedDCIDsMu.Unlock()
	if _, ok := usedDCIDs["still-replayable"]; !ok {
		t.Fatal("replay record evicted before full timestamp window closed")
	}
	if _, ok := usedDCIDs["expired"]; ok {
		t.Fatal("old record not cleaned")
	}
}

func FuzzExtractDCIDBounded(f *testing.F) {
	f.Add([]byte{0x40, 1, 2, 3})
	f.Add(append([]byte{0x40}, bytes.Repeat([]byte{7}, 20)...))
	f.Add([]byte{0xC0, 0, 0, 0, 1, 255})
	f.Fuzz(func(t *testing.T, p []byte) {
		before := bytes.Clone(p)
		cid := extractDCID(p)
		if !bytes.Equal(before, p) {
			t.Fatal("input mutated")
		}
		if len(cid) > 20 {
			t.Fatal("oversized CID")
		}
		if len(p) > 0 && p[0]&0xC0 == 0 && cid != "" {
			t.Fatal("short header without fixed bit")
		}
	})
}
func TestDemuxOutgoingClientCIDNotAdmitted(t *testing.T) {
	d := &DemuxPacketConn{rawConn: &packetDiscard{}, authClients: NewShardedAuthMap(), authCIDs: NewShardedAuthMap()}
	packet := bytes.Repeat([]byte{7}, 1200)
	packet[0] = 0x40
	_, err := d.WriteTo(packet, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 54321})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.authCIDs.Get(string(packet[1:17])); ok {
		t.Fatal("outgoing client CID authorized as server CID")
	}
}
func TestDemuxKnownAddressDoesNotAdmitCIDlessPacket(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDemuxPacketConn(raw, nil, "")
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer d.Close()
	sender, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	d.authClients.Set(sender.LocalAddr().String(), time.Now())
	_, err = sender.WriteTo([]byte{1, 2, 3, 4, 5}, raw.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	_ = d.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	_, _, err = d.ReadFrom(make([]byte, 1500))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("CID-less probe admitted: %v", err)
	}
}
func TestAuthRefreshCoalescesWithoutRevivingExpiredCID(t *testing.T) {
	m := NewShardedAuthMap()
	now := time.Now()
	m.Set("valid", now)
	if !m.RefreshExisting("valid", now.Add(500*time.Millisecond), 5*time.Minute) {
		t.Fatal("recent CID rejected")
	}
	got, _ := m.Get("valid")
	if !got.Equal(now) {
		t.Fatal("per-packet timestamp update")
	}
	if m.RefreshExisting("valid", now.Add(5*time.Minute), 5*time.Minute) {
		t.Fatal("expired CID revived")
	}
}
