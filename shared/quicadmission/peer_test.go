package quicadmission

import "testing"

func TestPeerBoundPacketRejectsOtherIPWithoutConsumingToken(t *testing.T) {
	s := testStore(t, 64, 64)
	b, err := s.IssueBoundForPeer("alice", 1, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	token := b.Tokens[0]
	digest := [32]byte{9}
	if err := s.RegisterPacket("alice", token, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdmitPacketFromPeer(token, Attempt{2}, digest, "192.0.2.2"); err == nil {
		t.Fatal("copied Initial admitted from other IP")
	}
	if _, err := s.AdmitPacket(token, Attempt{2}, digest); err == nil {
		t.Fatal("legacy API bypassed peer binding")
	}
	if _, err := s.AdmitPacketFromPeer(token, Attempt{1}, digest, "::ffff:192.0.2.1"); err != nil {
		t.Fatal("original peer lost admission", err)
	}
	if _, err := s.AdmitPacketFromPeer(token, Attempt{2}, digest, "192.0.2.1"); err == nil {
		t.Fatal("competing attempt accepted")
	}
}
