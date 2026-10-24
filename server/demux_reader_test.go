package main

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDemuxReaderPreservesPacketsAndPeer(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			raw, err := net.ListenPacket(network, address)
			if err != nil {
				t.Skipf("network unavailable: %v", err)
			}
			defer raw.Close()
			if udp, ok := raw.(*net.UDPConn); ok {
				_ = udp.SetReadBuffer(1 << 20)
			}
			sender, err := net.Dial(network, raw.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			_ = raw.SetReadDeadline(time.Now().Add(3 * time.Second))
			// Establish that the host delivers plain loopback datagrams before
			// testing the reader (some Windows VPNs intercept IPv6 loopback).
			if _, err := sender.Write([]byte{255}); err != nil {
				t.Fatal(err)
			}
			var probe [1]byte
			if _, _, err := raw.ReadFrom(probe[:]); err != nil {
				if network == "udp6" {
					t.Skipf("host IPv6 loopback unavailable before reader: %v", err)
				}
				t.Fatal(err)
			}
			reader := newDemuxPacketReader(raw)
			var packets [][]byte
			for i := 0; i < 33; i++ {
				want := bytes.Repeat([]byte{byte(i)}, []int{1, 1200, 1250, 1400, 3000}[i%5])
				packets = append(packets, want)
				if _, err := sender.Write(want); err != nil {
					t.Fatal(err)
				}
			}
			for i, want := range packets {
				got, peer, err := reader.ReadPacket()
				if err != nil || !bytes.Equal(got, want) || peer.String() != sender.LocalAddr().String() {
					t.Fatalf("packet %d lost, changed or misattributed: peer=%v err=%v", i, peer, err)
				}
			}
			large := bytes.Repeat([]byte{99}, 16384)
			if _, err := sender.Write(large); err != nil {
				t.Fatal(err)
			}
			got, _, err := reader.ReadPacket()
			if err != nil || !bytes.Equal(got, large) {
				t.Fatal("large datagram truncated", err)
			}
			_ = raw.Close()
			for i := 0; i < 2; i++ {
				if _, _, err := reader.ReadPacket(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed socket read %d: %v", i, err)
				}
			}
		})
	}
}
