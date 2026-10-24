package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestDemuxReadDeadlineWakesBlockedReader(t *testing.T) {
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
	result := make(chan error, 1)
	go func() { _, _, err := d.ReadFrom(make([]byte, 64)); result <- err }()
	if err := d.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not wake reader")
	}
	_ = d.SetReadDeadline(time.Time{})
	go func() { _, _, err := d.ReadFrom(make([]byte, 64)); result <- err }()
	d.dispatchToQUIC([]byte("hello"), raw.LocalAddr())
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cleared deadline did not allow read")
	}
	go func() { _, _, err := d.ReadFrom(make([]byte, 64)); result <- err }()
	_ = d.Close()
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake reader")
	}
}

func TestDemuxPreservesLargeDatagram(t *testing.T) {
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
	packet := make([]byte, 8192)
	packet[len(packet)-1] = 77
	d.dispatchToQUIC(packet, raw.LocalAddr())
	received := make([]byte, len(packet))
	n, _, err := d.ReadFrom(received)
	if err != nil || n != len(packet) || received[n-1] != 77 {
		t.Fatalf("truncated datagram: n=%d err=%v", n, err)
	}
}
