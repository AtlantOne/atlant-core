package quicadmission

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t testing.TB, capacity, perSubject int) *Store {
	t.Helper()
	s, err := NewStore(Options{Capacity: capacity, PerSubject: perSubject, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func issueOne(t testing.TB, s *Store, subject string) Token {
	t.Helper()
	b, err := s.Issue(subject, 1)
	if err != nil {
		t.Fatal(err)
	}
	return b.Tokens[0]
}

func requireRejected(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected rejection, got %v", err)
	}
}

func TestAdmissionLifecycle(t *testing.T) {
	s := testStore(t, 8, 4)
	token := issueOne(t, s, "alice")
	a, other := Attempt{1}, Attempt{2}
	requireRejected(t, s.Commit(token, a, "alice"))
	_, err := s.Admit(token, Attempt{})
	requireRejected(t, err)
	for i := 0; i < 3; i++ {
		subject, err := s.Admit(token, a)
		if err != nil || subject != "alice" {
			t.Fatalf("retransmission %d: subject=%q, error=%v", i, subject, err)
		}
	}
	_, err = s.Admit(token, other)
	requireRejected(t, err)
	requireRejected(t, s.Commit(token, other, "alice"))
	requireRejected(t, s.Retire(token, other))
	if err := s.Commit(token, a, "alice"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Admit(token, a)
	requireRejected(t, err)
	requireRejected(t, s.Commit(token, a, "alice"))
	requireRejected(t, s.Retire(token, a))
	if tokens, subjects := s.Counts(); tokens != 1 || subjects != 1 {
		t.Fatal("spent tombstone removed early")
	}
}

func TestFailedAttemptBurnsToken(t *testing.T) {
	for _, wrongSubject := range []bool{false, true} {
		s := testStore(t, 2, 2)
		token := issueOne(t, s, "alice")
		a := Attempt{1}
		if _, err := s.Admit(token, a); err != nil {
			t.Fatal(err)
		}
		if wrongSubject {
			requireRejected(t, s.Commit(token, a, "bob"))
		} else if err := s.Retire(token, a); err != nil {
			t.Fatal(err)
		}
		_, err := s.Admit(token, a)
		requireRejected(t, err)
		_, err = s.Admit(token, Attempt{2})
		requireRejected(t, err)
	}
}

func TestIssueAtomicityAndCapacity(t *testing.T) {
	s := testStore(t, 3, 2)
	issueOne(t, s, "alice")
	if _, err := s.Issue("alice", 2); !errors.Is(err, ErrCapacity) {
		t.Fatalf("per-subject quota: %v", err)
	}
	if n, _ := s.Counts(); n != 1 {
		t.Fatal("partial over-quota issue")
	}
	if _, err := s.Issue("bob", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue("charlie", 1); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if n, subjects := s.Counts(); n != 3 || subjects != 2 {
		t.Fatalf("counts=%d/%d", n, subjects)
	}
}

func TestEntropyFailuresDoNotPartiallyIssue(t *testing.T) {
	for _, input := range [][]byte{nil, make([]byte, TokenSize+1), make([]byte, TokenSize*2)} {
		s := testStore(t, 8, 8)
		s.random = bytes.NewReader(input)
		if _, err := s.Issue("alice", 2); !errors.Is(err, ErrEntropy) {
			t.Fatalf("expected entropy error: %v", err)
		}
		if n, _ := s.Counts(); n != 0 || len(s.expiry) != 0 {
			t.Fatal("failed batch inserted")
		}
	}
	s := testStore(t, 8, 8)
	raw := bytes.Repeat([]byte{3}, TokenSize)
	s.random = bytes.NewReader(raw)
	issueOne(t, s, "alice")
	s.random = bytes.NewReader(raw)
	if _, err := s.Issue("bob", 1); !errors.Is(err, ErrEntropy) {
		t.Fatalf("existing collision: %v", err)
	}
	if n, subjects := s.Counts(); n != 1 || subjects != 1 {
		t.Fatal("collision mutated store")
	}
}

func TestExpiryAndRevokeBoundMemory(t *testing.T) {
	s := testStore(t, 4, 4)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	b, err := s.Issue("alice", 4)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	_, err = s.Admit(b.Tokens[0], Attempt{1})
	requireRejected(t, err)
	if n, _ := s.Counts(); n != 3 {
		t.Fatal("lookup did not delete just the expired entry")
	}
	issueOne(t, s, "bob")
	if n, subjects := s.Counts(); n != 1 || subjects != 1 {
		t.Fatal("issuance did not prune expired entries")
	}
	for i := 0; i < 1000; i++ {
		if _, err := s.Issue("alice", 3); err != nil {
			t.Fatal(err)
		}
		s.RevokeSubject("alice")
		if len(s.expiry) != 1 || len(s.entries) != 1 || len(s.subjects) != 1 {
			t.Fatal("revoke leaked entries or heap items")
		}
	}
	s.RevokeSubject("bob")
	if len(s.expiry) != 0 || len(s.entries) != 0 || len(s.subjects) != 0 {
		t.Fatal("final revoke failed")
	}
}

func TestConcurrentClaimHasOneWinner(t *testing.T) {
	s := testStore(t, 2, 2)
	token := issueOne(t, s, "alice")
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := 1; i <= 128; i++ {
		wg.Add(1)
		go func(id byte) {
			defer wg.Done()
			if _, err := s.Admit(token, Attempt{id}); err == nil {
				winners.Add(1)
			}
		}(byte(i))
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
}

func TestConcurrentIssueHonorsQuota(t *testing.T) {
	s := testStore(t, 32, 16)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Issue("alice", 1)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrCapacity) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, subjects := s.Counts(); successes.Load() != 16 || n != 16 || subjects != 1 {
		t.Fatalf("quota race: success=%d entries=%d subjects=%d", successes.Load(), n, subjects)
	}
}

func TestUnknownTrafficDoesNotGrowStore(t *testing.T) {
	s := testStore(t, 2, 2)
	issueOne(t, s, "alice")
	for i := 0; i < 10000; i++ {
		_, err := s.Admit(Token{byte(i), byte(i >> 8)}, Attempt{1})
		requireRejected(t, err)
	}
	if n, subjects := s.Counts(); n != 1 || subjects != 1 || len(s.expiry) != 1 {
		t.Fatal("unknown packets allocated persistent state")
	}
	allocs := testing.AllocsPerRun(1000, func() { _, _ = s.Admit(Token{}, Attempt{1}) })
	if allocs != 0 {
		t.Fatalf("unknown admission allocates: %f", allocs)
	}
}

func TestRestartFailsClosed(t *testing.T) {
	before := testStore(t, 2, 2)
	token := issueOne(t, before, "alice")
	after := testStore(t, 2, 2)
	_, err := after.Admit(token, Attempt{1})
	requireRejected(t, err)
}

func TestValidation(t *testing.T) {
	for _, o := range []Options{{}, {Capacity: 2, PerSubject: 3, TTL: time.Minute}, {Capacity: 1, PerSubject: 1, TTL: time.Millisecond}, {Capacity: 1 << 21, PerSubject: 1, TTL: time.Minute}, {Capacity: 1, PerSubject: 1, TTL: time.Hour + 1}} {
		if _, err := NewStore(o); !errors.Is(err, ErrOptions) {
			t.Fatalf("accepted options: %+v", o)
		}
	}
	s := testStore(t, 2, 2)
	for _, count := range []int{0, -1, MaxBatch + 1} {
		if _, err := s.Issue("alice", count); !errors.Is(err, ErrOptions) {
			t.Fatal(err)
		}
	}
	if _, err := s.Issue("", 1); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	if _, err := s.Issue(string(bytes.Repeat([]byte{'a'}, 257)), 1); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	for _, size := range []int{0, 19, 21} {
		_, err := ParseToken(make([]byte, size))
		requireRejected(t, err)
	}
	raw := bytes.Repeat([]byte{7}, 20)
	token, err := ParseToken(raw)
	if err != nil || !bytes.Equal(raw, token[:]) {
		t.Fatal("exact length rejected")
	}
	raw[0] = 1
	if token[0] != 7 {
		t.Fatal("ParseToken did not copy input")
	}
}

func FuzzParseToken(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 20))
	f.Add(make([]byte, 21))
	f.Fuzz(func(t *testing.T, raw []byte) {
		token, err := ParseToken(raw)
		if len(raw) == 20 {
			if err != nil || !bytes.Equal(raw, token[:]) {
				t.Fatal("bad roundtrip")
			}
		} else if !errors.Is(err, ErrRejected) {
			t.Fatal("invalid size accepted")
		}
	})
}

// Deterministic test entropy only, never used by production issuance.
type sequenceReader struct{ next uint64 }

func (r *sequenceReader) Read(p []byte) (int, error) {
	r.next++
	clear(p)
	binary.LittleEndian.PutUint64(p, r.next)
	return len(p), nil
}

func FuzzAdmissionStateMachine(f *testing.F) {
	f.Add([]byte{0, 0, 1, 2, 3, 4, 5, 6, 7})
	f.Add(bytes.Repeat([]byte{0, 1, 2, 4, 6}, 30))
	f.Fuzz(func(t *testing.T, events []byte) {
		if len(events) > 512 {
			events = events[:512]
		}
		s := testStore(t, 16, 8)
		s.random = &sequenceReader{}
		now := time.Unix(1000, 0)
		s.now = func() time.Time { return now }
		var tokens []Token
		for i, event := range events {
			subject := "alice"
			if event&8 != 0 {
				subject = "bob"
			}
			attempt := Attempt{(event >> 4) & 7}
			var token Token
			if len(tokens) > 0 {
				token = tokens[i%len(tokens)]
			}
			switch event & 7 {
			case 0:
				batch, err := s.Issue(subject, 1+int(event>>6))
				if err == nil {
					tokens = append(tokens, batch.Tokens...)
				} else if !errors.Is(err, ErrCapacity) {
					t.Fatal(err)
				}
			case 1:
				_, _ = s.Admit(token, attempt)
			case 2:
				_ = s.Commit(token, attempt, subject)
			case 3:
				_ = s.Retire(token, attempt)
			case 4:
				s.RevokeSubject(subject)
			case 5:
				now = now.Add(30 * time.Second)
			case 6:
				_, _ = s.Admit(Token{255}, attempt)
			case 7:
				_, _ = s.Counts()
			}
			if len(s.entries) > 16 || len(s.expiry) != len(s.entries) {
				t.Fatal("entry/heap capacity invariant")
			}
			counts := map[string]int{}
			for index, e := range s.expiry {
				if e.index != index || s.entries[e.digest] != e {
					t.Fatal("heap index invariant")
				}
				if index > 0 && e.expires.Before(s.expiry[(index-1)/2].expires) {
					t.Fatal("heap ordering invariant")
				}
				if e.state == issued && e.attempt != (Attempt{}) {
					t.Fatal("issued token has claim")
				}
				if e.state != issued && e.attempt == (Attempt{}) {
					t.Fatal("claimed/spent token has no attempt")
				}
				counts[e.subject]++
			}
			if len(counts) != len(s.subjects) {
				t.Fatal("subject index invariant")
			}
			for subject, count := range counts {
				if count > 8 || s.subjects[subject] != count {
					t.Fatal("subject quota invariant")
				}
			}
		}
	})
}

func BenchmarkUnknownAdmission(b *testing.B) {
	for _, size := range []int{1, 256, 65536} {
		name := strconv.Itoa(size)
		b.Run(name, func(b *testing.B) {
			s := testStore(b, size, size)
			for left := size; left > 0; {
				count := min(left, MaxBatch)
				if _, err := s.Issue("alice", count); err != nil {
					b.Fatal(err)
				}
				left -= count
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Admit(Token{}, Attempt{1}); !errors.Is(err, ErrRejected) {
					b.Fatal("unexpected acceptance")
				}
			}
		})
	}
}
