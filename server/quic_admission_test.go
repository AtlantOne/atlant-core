package main

import (
	"atlant.local/protocol/quicadmission"
	"atlant.local/protocol/realityauth"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
)

func admissionInitial(token quicadmission.Token, version uint32) []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	if version != 1 {
		p[0] = 0xd0
	}
	binary.BigEndian.PutUint32(p[1:5], version)
	p[5] = 8
	copy(p[6:14], []byte("original"))
	p[14] = 20
	copy(p[15:35], token[:])
	return p
}

func TestAdmissionInitialAttemptBindingReplayUnknownAndRestart(t *testing.T) {
	g, err := newAdmissionGate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.store.Issue("alice", 1)
	if err != nil {
		t.Fatal(err)
	}
	peer := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}
	p := admissionInitial(b.Tokens[0], 1)
	if !g.admit(p, peer) || !g.admit(p, peer) {
		t.Fatal("valid Initial or retransmission rejected")
	}
	changed := append([]byte(nil), p...)
	changed[6] ^= 1
	if g.admit(changed, peer) {
		t.Fatal("token admitted on different original DCID")
	}
	if g.admit(p, &net.UDPAddr{IP: peer.IP, Port: 1235}) {
		t.Fatal("token admitted from competing peer")
	}
	if g.admit(admissionInitial(b.Tokens[0], 0x6b3343cf), peer) {
		t.Fatal("cross-version attempt reused token")
	}
	for i := 0; i < 10000; i++ {
		unknown := p
		copy := append([]byte(nil), unknown...)
		binary.BigEndian.PutUint32(copy[15:19], uint32(i))
		copy[34] ^= 1
		if g.admit(copy, peer) {
			t.Fatal("unknown token accepted")
		}
	}
	if len(g.pending) != 1 {
		t.Fatal("unknown packets allocated pending entries")
	}
	token, attempt, _, _ := initialAdmissionFields(p, peer)
	if g.store.Commit(token, attempt, "bob") == nil {
		t.Fatal("wrong authenticated owner accepted")
	}
	if g.admit(p, peer) {
		t.Fatal("spent token reused")
	}
	restarted, _ := newAdmissionGate()
	if restarted.admit(p, peer) {
		t.Fatal("restart resurrected token")
	}
}

func TestReality3SessionReplayAndExplicitLegacyPolicy(t *testing.T) {
	isolateUsers(t)
	isolateReplay(t)
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previous := serverStaticECDH
	serverStaticECDH = server
	defer func() { serverStaticECDH = previous }()
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key, _ := hex.DecodeString(strings.Repeat("ab", 32))
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	token, err := realityauth.Generate("alice", key, client, server.PublicKey().Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, ok := authenticateSessionID(token[:], client.PublicKey().Bytes()); ok {
		t.Fatal("legacy server accepted new format")
	}
	cfg.WireVersion = 3
	cfg.LegacyWire = false
	if name, _, _, _, _, ok, version := authenticateSessionIDWire(token[:], client.PublicKey().Bytes()); !ok || name != "alice" || version != 3 {
		t.Fatal("new format rejected")
	}
	if _, _, _, _, _, ok := authenticateSessionID(token[:], client.PublicKey().Bytes()); ok {
		t.Fatal("replay accepted")
	}
	legacy := sessionFixture(uint32(time.Now().Unix()), client.PublicKey().Bytes(), key)
	if _, _, _, _, _, ok := authenticateSessionID(legacy, client.PublicKey().Bytes()); ok {
		t.Fatal("implicit old-format acceptance")
	}
	cfg.LegacyWire = true
	if _, _, _, _, _, ok, version := authenticateSessionIDWire(legacy, client.PublicKey().Bytes()); !ok || version != 2 {
		t.Fatal("explicit coexistence rejected")
	}
}

func TestRealityAdmissionRejectsLegacyBootstrap(t *testing.T) {
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	g, _ := newAdmissionGate()
	previous := activeAdmission.Swap(g)
	defer activeAdmission.Store(previous)
	client, server := net.Pipe()
	go handleStream(server, "alice", 2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := quicadmission.FetchPool(ctx, client); err == nil {
		t.Fatal("bootstrap accepted on linkable legacy handshake")
	}
	if n, _ := g.store.Counts(); n != 0 {
		t.Fatal("rejected bootstrap issued state")
	}
}
