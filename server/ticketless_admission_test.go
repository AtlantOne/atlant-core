package main

import (
	"atlant.local/protocol/realityauth"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestWire6AdmissionHasNoTicketDependencyAndCommitsReplayLate(t *testing.T) {
	isolateUsers(t)
	isolateReplay(t)
	previous := serverStaticECDH
	serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
	defer func() { serverStaticECDH = previous }()
	cfg.WireVersion, cfg.LegacyWire = 6, false
	key := bytes.Repeat([]byte{9}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	if err := usersStorage.AddUser("alice", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hello := make([]byte, 128)
	hello[0], hello[3], hello[38] = 1, 124, 32
	record := append([]byte{22, 3, 1, 0, 128}, hello...)
	if err := realityauth.BindHelloRecord(record, "alice", key, client, serverStaticECDH.PublicKey().Bytes(), time.Now()); err != nil {
		t.Fatal(err)
	}
	hello = record[5:]
	token := hello[39:71]
	pub := client.PublicKey().Bytes()
	for i := 0; i < 2; i++ {
		name, _, _, _, replay, ok, version := authenticateSessionIDWire(token, pub, hello)
		if !ok || replay || name != "alice" || version != 6 {
			t.Fatalf("pre-Finished admission failed: %s %v %v %d", name, replay, ok, version)
		}
	}
	changed := bytes.Clone(hello)
	changed[100] ^= 1
	if _, _, _, _, _, ok, _ := authenticateSessionIDWire(token, pub, changed); ok {
		t.Fatal("modified Hello admitted")
	}
	cacheKey := "wire6:" + hex.EncodeToString(token) + hex.EncodeToString(pub)
	if !consumeAuthToken(cacheKey) || consumeAuthToken(cacheKey) {
		t.Fatal("Finished commit is not one-shot")
	}
	if _, _, _, _, replay, ok, _ := authenticateSessionIDWire(token, pub, hello); ok || !replay {
		t.Fatal("completed handshake replay admitted")
	}
	cfg.WireVersion = 4
	if _, _, _, _, _, ok, _ := authenticateSessionIDWire(token, pub, hello); ok {
		t.Fatal("wire6 silently downgraded")
	}
}
