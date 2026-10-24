package main

import (
	"atlant.local/protocol/quicpeer"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestDirectGateRejectsWrongPSKAndPinnedKeyBeforePrivateTLS(t *testing.T) {
	isolateUsers(t)
	cfg.WireVersion, cfg.LegacyWire = 7, false
	previous := serverStaticECDH
	defer func() { serverStaticECDH = previous }()
	serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{9}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	if err := usersStorage.AddUser("alice", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	serverSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	demux, err := NewDemuxPacketConn(serverSocket, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer demux.Close()
	wrong, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, creds := range []quicpeer.DirectCredentials{
		{User: "alice", Key: bytes.Repeat([]byte{8}, 32), ServerPublicKey: serverStaticECDH.PublicKey().Bytes()},
		{User: "alice", Key: key, ServerPublicKey: wrong.PublicKey().Bytes()},
	} {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		conn, closer, err := quicpeer.DialClient(ctx, &quic.Transport{Conn: packet}, demux.LocalAddr(), &tls.Config{ServerName: "localhost"}, quicpeer.ClientConfig(), 7, creds)
		cancel()
		if closer != nil {
			closer.Close()
		}
		packet.Close()
		if conn != nil {
			conn.CloseWithError(0, "unexpected")
		}
		if err == nil {
			t.Fatal("invalid credentials connected")
		}
		select {
		case <-demux.authQueue:
			t.Fatal("invalid admission reached private TLS queue")
		default:
		}
	}
}
