package quicadmission

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestWire6RegistersInitialFlightBeforeUDPRelease(t *testing.T) {
	store := testStore(t, 64, 64)
	batch, err := store.IssueBound("alice", 1)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		var request [4]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			serverDone <- err
			return
		}
		if request[0] != 0x15 {
			serverDone <- ErrRejected
			return
		}
		if err := WriteBatchVersion(server, batch, 6); err != nil {
			serverDone <- err
			return
		}
		serverDone <- ServeBoundFlightRegistrations(server, store, "alice", batch)
	}()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, bound, err := FetchBoundPoolVersion(ctx, client, socket, 6)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Close()
	for i := 0; i < 2; i++ {
		p := boundInitial(batch.Tokens[0])
		p[100] = byte(i)
		if _, err := bound.WriteTo(p, sink.LocalAddr()); err != nil {
			t.Fatal(err)
		}
	}
	_ = sink.SetReadDeadline(time.Now().Add(time.Second))
	for i := 0; i < 2; i++ {
		var buffer [1500]byte
		n, _, err := sink.ReadFrom(buffer[:])
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := store.ResolvePacket(PacketDigest(buffer[:n])); !ok {
			t.Fatal("UDP released before authenticated registration")
		}
	}
	bound.CloseBootstrap()
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("control handler leaked")
	}
}
