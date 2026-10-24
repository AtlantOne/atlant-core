package quicadmission

import (
	"testing"
	"time"
)

func FuzzBoundAdmissionState(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, program []byte) {
		if len(program) > 256 {
			t.Skip()
		}
		s := testStore(t, 8, 8)
		now := time.Unix(1800000000, 0)
		s.now = func() time.Time { return now }
		batch, err := s.IssueBound("alice", 1)
		if err != nil {
			t.Fatal(err)
		}
		token := batch.Tokens[0]
		for _, op := range program {
			digest := [32]byte{op / 8}
			switch op % 8 {
			case 0:
				_ = s.RegisterPacket("alice", token, digest)
			case 1:
				if err := s.RegisterPacket("bob", token, digest); err == nil {
					t.Fatal("wrong owner registered")
				}
			case 2:
				_, _ = s.AdmitPacket(token, Attempt{1}, digest)
			case 3:
				_ = s.Commit(token, Attempt{1}, "alice")
			case 4:
				_ = s.Retire(token, Attempt{1})
			case 5:
				now = now.Add(time.Minute)
				_, _ = s.ResolvePacket(digest)
			case 6:
				s.RevokeSubject("alice")
			case 7:
				s.RevokeAll()
			}
			count := 0
			for _, entry := range s.entries {
				count += len(entry.packets)
				if entry.state == spent && len(entry.packets) != 0 {
					t.Fatal("spent registration retained")
				}
			}
			if count != s.packetCount || count != len(s.registered) || count > maxRegisteredPackets {
				t.Fatal("registration accounting mismatch")
			}
			subjectCount := 0
			for _, n := range s.packetSubjects {
				if n <= 0 || n > maxPacketsPerSubject {
					t.Fatal("invalid subject quota")
				}
				subjectCount += n
			}
			if subjectCount != count {
				t.Fatal("subject registration accounting mismatch")
			}
		}
	})
}
