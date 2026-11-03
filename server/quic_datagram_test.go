package main

import (
	"atlant.local/protocol/wire"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestQUICDatagramRelayIsolatesDNSAndPreservesSocket(t *testing.T) {
	isolateUsers(t)
	usersDB.Users["alice"] = &userRecord{Name: "alice", Enabled: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	peers := make(chan string, 8)
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, peer, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			peers <- peer.String()
			response := buffer[:n]
			if n == 32 {
				response = bytes.Repeat([]byte{9}, 2000)
			}
			echo.WriteToUDP(response, peer)
		}
	}()
	input, output := make(chan []byte, 256), make(chan []byte, 256)
	slowStarted := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayDatagramFlows(ctx, func(ctx context.Context) ([]byte, error) {
			select {
			case p := <-input:
				return p, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, func(p []byte) error {
			if len(p) > 1150 {
				return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
			}
			select {
			case output <- append([]byte(nil), p...):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, nil, "alice", func(ctx context.Context, target string) (*net.UDPAddr, error) {
			if target == "slow.example:22023" {
				close(slowStarted)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return echo.LocalAddr().(*net.UDPAddr), nil
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Relay did not stop")
		}
	}()
	send := func(target string, id uint32, payload []byte) {
		packet := make([]byte, 10+len(target)+len(payload))
		tag := getUserTag("alice")
		copy(packet, tag[:])
		binary.BigEndian.PutUint32(packet[4:], id)
		binary.BigEndian.PutUint16(packet[8:], uint16(len(target))|wire.DatagramFragmentsSupported)
		copy(packet[10:], target)
		copy(packet[10+len(target):], payload)
		if err := wire.SendTunnelDatagram(packet, 8, func(p []byte) error {
			if len(p) > 1150 {
				return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
			}
			input <- append([]byte(nil), p...)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	send("slow.example:22023", 1, []byte{1})
	select {
	case <-slowStarted:
	case <-time.After(time.Second):
		t.Fatal("Slow resolver did not start")
	}
	var assembler wire.DatagramAssembler
	var originalPeer string
	for _, size := range []int{32, 1300, 8192, 65507} {
		payload := bytes.Repeat([]byte{7}, size)
		send("game.example:22023", 2, payload)
		want := payload
		if size == 32 {
			want = bytes.Repeat([]byte{9}, 2000)
		}
		deadline := time.After(time.Second)
		for {
			var packet []byte
			select {
			case packet = <-output:
			case <-deadline:
				t.Fatalf("Response stalled with slow DNS, size %d", size)
			}
			packet, complete := assembler.Decode(packet, 4, time.Now())
			if !complete {
				continue
			}
			destLen := int(binary.BigEndian.Uint16(packet[4:6]))
			if !bytes.Equal(packet[6+destLen:], want) {
				t.Fatal("Corrupted UDP payload")
			}
			break
		}
		peer := <-peers
		if originalPeer == "" {
			originalPeer = peer
		} else if originalPeer != peer {
			t.Fatal("UDP source socket changed after large packet")
		}
	}
}
