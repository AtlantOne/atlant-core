package quicadmission

import "testing"

func TestBoundReconnectsReclaimUnusedTokensWithoutWireChange(t *testing.T) {
	store := testStore(t, 65536, 1024)
	if BoundBatchSize != 32 {
		t.Fatal("wire4 framing changed without a version change")
	}
	for i := 0; i < 100; i++ {
		batch, err := store.IssueBound("owner", BoundBatchSize)
		if err != nil {
			t.Fatalf("reconnect %d: %v", i, err)
		}
		if err := store.RetainBoundToken("owner", batch.Tokens, batch.Tokens[0]); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.subjects["owner"] != 100 {
		t.Fatalf("unused batch slots retained: %d", store.subjects["owner"])
	}
}

func TestBoundReclaimCannotCrossSubjectsOrBatches(t *testing.T) {
	store := testStore(t, 128, 128)
	one, _ := store.IssueBound("one", 32)
	two, _ := store.IssueBound("two", 32)
	if err := store.RetainBoundToken("one", one.Tokens, two.Tokens[0]); err == nil {
		t.Fatal("accepted foreign token")
	}
	if err := store.RetainBoundToken("two", one.Tokens, one.Tokens[0]); err == nil {
		t.Fatal("accepted foreign subject")
	}
	if err := store.RetainBoundToken("one", one.Tokens, one.Tokens[0]); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.subjects["two"] != 32 {
		t.Fatal("unrelated batch changed")
	}
}
