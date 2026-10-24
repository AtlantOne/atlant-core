package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

func TestQUICConnectionIDsStayWithTheirListener(t *testing.T) {
	first := &DemuxPacketConn{authCIDs: NewShardedAuthMap()}
	second := &DemuxPacketConn{authCIDs: NewShardedAuthMap()}
	generators := []*serverConnIDGenerator{{demux: first}, {demux: second}}
	for i := 0; i < 128; i++ {
		owner := i % 2
		cid, err := generators[owner].GenerateConnectionID()
		if err != nil || cid.Len() != 16 {
			t.Fatalf("CID generation: %v, %v", cid, err)
		}
		key := string(cid.Bytes())
		now := time.Now()
		if !generators[owner].demux.authCIDs.RefreshExisting(key, now, time.Minute) {
			t.Fatal("CID was not registered with its listener")
		}
		if generators[1-owner].demux.authCIDs.RefreshExisting(key, now, time.Minute) {
			t.Fatal("CID leaked into the other listener's admission table")
		}
	}
	if _, err := (&serverConnIDGenerator{}).GenerateConnectionID(); err == nil {
		t.Fatal("unbound generator silently created an unusable CID")
	}
}

func TestQUICDemuxCapturesItsOwnPolicy(t *testing.T) {
	identity, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	for _, version := range []int{0, 6, 7} {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		d, err := newDemuxPacketConn(socket, nil, "", version, false, nil, identity)
		if err != nil {
			socket.Close()
			t.Fatal(err)
		}
		if (d.direct != nil) != (version == 7) {
			t.Fatal("direct admission uses another listener's policy")
		}
		if d.direct != nil && d.direct.identity != identity {
			t.Fatal("direct admission did not retain its listener's identity")
		}
		if (d.QUICSendSocket() != nil) != (version == 7) {
			t.Fatal("send socket exposure uses global policy")
		}
		d.dispatchToQUIC([]byte{1}, peer)
		_, addr, err := d.ReadFrom(make([]byte, 1))
		if err != nil {
			t.Fatal(err)
		}
		_, wrapped := addr.(retryPeerAddr)
		if wrapped != (version == 6 || version == 7) {
			t.Fatal("Retry address binding uses global policy")
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
