package quicadmission

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func boundInitial(_ Token) []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	binary.BigEndian.PutUint32(p[1:5], 1)
	p[5] = 8
	copy(p[6:14], []byte("original"))
	p[14] = 0
	return p
}

func TestBoundAdmissionRejectsCopiedCIDWithChangedDatagram(t *testing.T) {
	s := testStore(t, 64, 64)
	batch, err := s.IssueBound("alice", 1)
	if err != nil {
		t.Fatal(err)
	}
	token := batch.Tokens[0]
	p := boundInitial(token)
	digest := PacketDigest(p)
	a := Attempt{1}
	if _, err := s.Admit(token, a); err == nil {
		t.Fatal("unbound admission bypassed wire4")
	}
	if _, err := s.AdmitPacket(token, a, digest); err == nil {
		t.Fatal("unregistered datagram admitted")
	}
	if err := s.RegisterPacket("bob", token, digest); err == nil {
		t.Fatal("other user registered token")
	}
	if err := s.RegisterPacket("alice", token, digest); err != nil {
		t.Fatal(err)
	}
	p[100] ^= 1
	if _, err := s.AdmitPacket(token, a, PacketDigest(p)); err == nil {
		t.Fatal("changed hello with copied CID admitted")
	}
	if _, err := s.AdmitPacket(token, a, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdmitPacket(token, Attempt{2}, digest); err == nil {
		t.Fatal("competing peer claimed token")
	}
	if err := s.Commit(token, a, "alice"); err != nil {
		t.Fatal(err)
	}
	if s.packetCount != 0 {
		t.Fatal("spent token retained packet registrations")
	}
	if err := s.RegisterPacket("alice", token, digest); err == nil {
		t.Fatal("spent token revived")
	}
	if _, err := s.AdmitPacket(token, a, digest); err == nil {
		t.Fatal("spent packet replay admitted")
	}
}

func TestBoundPacketRegistrationQuota(t *testing.T) {
	s := testStore(t, 64, 64)
	batch, err := s.IssueBound("alice", 1)
	if err != nil {
		t.Fatal(err)
	}
	token := batch.Tokens[0]
	for i := 0; i < MaxPacketsPerToken; i++ {
		if err := s.RegisterPacket("alice", token, [32]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RegisterPacket("alice", token, [32]byte{255}); err != ErrCapacity {
		t.Fatal("unbounded registrations", err)
	}
	s.RevokeSubject("alice")
	if s.packetCount != 0 {
		t.Fatal("revoke leaked packet quota")
	}
}

func TestBoundPacketConnRegistersBeforeSendingAndKeepsUDPBytes(t *testing.T) {
	s := testStore(t, 64, 64)
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		var request [4]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			done <- err
			return
		}
		if request != [4]byte{0x14, 0, 0, 0} {
			done <- ErrRejected
			return
		}
		batch, err := s.IssueBound("alice", BootstrapBatchSize)
		if err == nil {
			err = WriteBatchVersion(server, batch, 4)
		}
		if err == nil {
			err = ServeBoundRegistrations(server, s, "alice")
		}
		done <- err
	}()
	_, bound, err := FetchBoundPool(context.Background(), client, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	token := bound.token
	p := boundInitial(token)
	if _, err := bound.WriteTo(p, sink.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = sink.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, _, err := sink.ReadFrom(buf)
	if err != nil || !bytes.Equal(buf[:n], p) {
		t.Fatal("UDP mutated/lost", err)
	}
	if _, err := s.AdmitPacket(token, Attempt{1}, PacketDigest(buf[:n])); err != nil {
		t.Fatal("sent before registration", err)
	}
	bound.CloseBootstrap()
	// Established traffic has no dependency on the control connection.
	if _, err := bound.WriteTo([]byte{0x40, 1}, sink.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err := bound.WriteTo(p, sink.LocalAddr()); err == nil {
		t.Fatal("Initial silently bypassed unavailable control")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control leaked")
	}
}
