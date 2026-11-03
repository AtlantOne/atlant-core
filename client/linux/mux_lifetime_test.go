package main

import (
	"atlant.local/protocol/wire"
	"github.com/hashicorp/yamux"
	"io"
	"net"
	"testing"
	"time"
)

func TestHealthyMuxSessionSurvivesOldAge(t *testing.T) {
	left, right := net.Pipe()
	config := yamux.DefaultConfig()
	config.EnableKeepAlive = false
	config.LogOutput = io.Discard
	client, err := yamux.Client(left, config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := yamux.Server(right, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		stream, err := server.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		io.Copy(stream, stream)
	}()
	stream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(35 * time.Second))
	if _, err = stream.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	var answer [4]byte
	if _, err = io.ReadFull(stream, answer[:]); err != nil || string(answer[:]) != "PING" {
		t.Fatal(err)
	}
	sessMu.Lock()
	previous, dead, connected, cooldown := session, sessionDead, lastConnectTime, sessionDialCooldown
	session, sessionDead, lastConnectTime, sessionDialCooldown = client, false, time.Now().Add(-13*time.Minute), wire.DialCooldown{}
	sessMu.Unlock()
	defer func() {
		sessMu.Lock()
		session, sessionDead, lastConnectTime, sessionDialCooldown = previous, dead, connected, cooldown
		sessMu.Unlock()
	}()
	kept, err := getYamuxSession(&Config{ServerAddr: "invalid-address", SNI: "example.com"})
	if err != nil || kept != client {
		t.Fatalf("Healthy old session was replaced: %v", err)
	}
	if _, err = stream.Write([]byte("PONG")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(stream, answer[:]); err != nil || string(answer[:]) != "PONG" {
		t.Fatal(err)
	}
	if client.IsClosed() {
		t.Fatal("Live session was closed")
	}

	stream.Close()
	client.Close()
	server.Close()
	<-echoDone
}
