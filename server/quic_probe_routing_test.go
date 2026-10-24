package main

import (
	"atlant.local/protocol/quicadmission"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestStrictAdmissionCannotBeBypassedWithCachedDCID(t *testing.T) {
	for _, version := range []int{3, 4} {
		t.Run(strconv.Itoa(version), func(t *testing.T) { testStrictAdmission(t, version) })
	}
}

func testStrictAdmission(t *testing.T, version int) {
	isolateUsers(t)
	cfg.WireVersion, cfg.LegacyWire = version, false
	gate, err := newAdmissionGate()
	if err != nil {
		t.Fatal(err)
	}
	previous := activeAdmission.Swap(gate)
	defer activeAdmission.Store(previous)
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	demux, err := NewDemuxPacketConn(raw, nil, "")
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	defer demux.Close()
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var batch quicadmission.Batch
	if version == 4 {
		batch, err = gate.store.IssueBound("alice", 1)
	} else {
		batch, err = gate.store.Issue("alice", 1)
	}
	if err != nil {
		t.Fatal(err)
	}
	initial := admissionInitial(batch.Tokens[0], 1)
	if version == 4 {
		initial = append(initial[:15], initial[35:]...)
		initial[14] = 0
		initial = append(initial, make([]byte, 20)...)
		if err := gate.store.RegisterPacket("alice", batch.Tokens[0], quicadmission.PacketDigest(initial)); err != nil {
			t.Fatal(err)
		}
	}
	readPacket := func(packet []byte, allowed bool) {
		t.Helper()
		_ = demux.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
		if _, err := peer.WriteTo(packet, raw.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, err := demux.ReadFrom(buf)
		if allowed {
			if err != nil || !bytes.Equal(buf[:n], packet) {
				t.Fatal("legitimate packet lost", err)
			}
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("cached CID bypassed Initial admission: n=%d err=%v", n, err)
		}
	}
	readPacket(initial, true)
	if version == 4 {
		changed := append([]byte(nil), initial...)
		changed[100] ^= 1
		readPacket(changed, false) // Same unused token, different protected hello.
	}
	readPacket(initial, true) // Initial retransmission before peer authentication.
	token, attempt, dcid, _ := initialAdmissionFields(initial, peer.LocalAddr())
	if version == 4 {
		token, attempt, dcid, _ = initialAdmissionFieldsKnown(initial, peer.LocalAddr(), &batch.Tokens[0])
	}
	if err := gate.store.Commit(token, attempt, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := demux.authCIDs.Get(dcid); !ok {
		t.Fatal("test did not seed the CID fast path")
	}
	readPacket(initial, false)
	for _, version := range []uint32{1, 0x6b3343cf, 0xdeadbeef} {
		probe := append([]byte(nil), initial...)
		binary.BigEndian.PutUint32(probe[1:5], version)
		if version == 0x6b3343cf {
			probe[0] = 0xd0
		}
		probe[15] ^= 1 // Known DCID, but no valid admission token.
		readPacket(probe, false)
	}
	// Established connections still route by their server CID after rebinding.
	serverCID := bytes.Repeat([]byte{0x67}, 16)
	demux.authCIDs.Set(string(serverCID), time.Now())
	rebound, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rebound.Close()
	packet := append([]byte{0x40}, serverCID...)
	_ = demux.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := rebound.WriteTo(packet, raw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, addr, err := demux.ReadFrom(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) || addr.String() != rebound.LocalAddr().String() {
		t.Fatal("established CID migration route was broken", err)
	}
}
