package main

import (
	"atlant.local/protocol/quicpeer"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestInitialClassificationSupportsUniqueCIDsAndQUICVersions(t *testing.T) {
	isolateUsers(t)
	key := bytes.Repeat([]byte{7}, 32)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
	_ = usersStorage.AddUser("alice", hex.EncodeToString(key))
	generator := quicpeer.NewCIDGenerator("alice", key)
	for _, version := range []uint32{1, 0x6b3343cf} {
		cid, err := generator.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		packet := make([]byte, 1200)
		packet[0] = 0xc0
		if version != 1 {
			packet[0] = 0xd0
		}
		binary.BigEndian.PutUint32(packet[1:5], version)
		packet[5] = 8
		packet[14] = 20
		copy(packet[15:35], cid.Bytes())
		original := append([]byte(nil), packet...)
		ok, user := validateQUICInitial(packet, nil)
		if !ok || user != "alice" {
			t.Fatalf("version %x rejected", version)
		}
		if !bytes.Equal(original, packet) {
			t.Fatal("classification modified the received datagram")
		}
	}
}
