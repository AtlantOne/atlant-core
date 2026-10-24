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

func TestTCPInboundRuntimeOwnsItsSettings(t *testing.T) {
	spec := inboundFixture("owned", "127.0.0.1:1026")
	identity, _ := ecdh.X25519().GenerateKey(rand.Reader)
	runtime, err := newTCPListenerRuntime(spec, identity)
	if err != nil {
		t.Fatal(err)
	}
	spec.SNI, spec.XHTTPPath, spec.Transports[0] = "changed.example.com", "/changed", "quic"
	spec.Yamux.WriteTimeoutSec = 999
	if runtime.config.SNI != "www.example.com" || runtime.config.Path != "/sync" || !runtime.tcp || !runtime.xhttp || runtime.config.Yamux.WriteTimeoutSec != 0 || runtime.legacyPath {
		t.Fatal("runtime retained mutable/default listener settings")
	}
	if _, err := newTCPListenerRuntime(inboundFixture("missing-key", "127.0.0.1:1027"), nil); err == nil {
		t.Fatal("missing identity accepted")
	}
	spec.Transports = []string{"quic"}
	if _, err := newTCPListenerRuntime(spec, identity); err == nil {
		t.Fatal("QUIC-only inbound started a TCP runtime")
	}
}

func TestListenerRealityAdmissionUsesItsOwnIdentity(t *testing.T) {
	isolateUsers(t)
	isolateReplay(t)
	key := bytes.Repeat([]byte{0x62}, 32)
	if err := usersStorage.AddUser("alice", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	first, _ := ecdh.X25519().GenerateKey(rand.Reader)
	second, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hello := make([]byte, 128)
	hello[0], hello[3], hello[38] = 1, 124, 32
	record := append([]byte{22, 3, 1, 0, 128}, hello...)
	if err := realityauth.BindHelloVersion(7, record, "alice", key, client, first.PublicKey().Bytes(), time.Now()); err != nil {
		t.Fatal(err)
	}
	hello = record[5:]
	settings := &Config{WireVersion: 7}
	name, _, _, _, _, allowed, version := authenticateSessionIDWithIdentity(settings, first, hello[39:71], client.PublicKey().Bytes(), hello)
	if !allowed || version != 7 || name != "alice" {
		t.Fatal("own inbound identity rejected")
	}
	_, _, _, _, _, allowed, _ = authenticateSessionIDWithIdentity(settings, second, hello[39:71], client.PublicKey().Bytes(), hello)
	if allowed {
		t.Fatal("another inbound's identity accepted the Hello")
	}
	_, _, _, _, _, allowed, _ = authenticateSessionIDWithIdentity(settings, nil, hello[39:71], client.PublicKey().Bytes(), hello)
	if allowed {
		t.Fatal("missing identity admitted a wire7 Hello")
	}
}
