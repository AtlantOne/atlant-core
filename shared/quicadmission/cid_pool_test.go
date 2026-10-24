package quicadmission

import (
	"errors"
	"sync"
	"testing"
)

func TestCIDPoolCopiesConsumesAndFailsClosed(t *testing.T) {
	tokens := []Token{{1}, {2}}
	p, err := NewCIDPool(tokens)
	if err != nil {
		t.Fatal(err)
	}
	tokens[0] = Token{9}
	if p.ConnectionIDLen() != 20 {
		t.Fatal("invalid CID length")
	}
	for _, want := range []Token{{1}, {2}} {
		cid, err := p.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseToken(cid.Bytes())
		if err != nil || got != want {
			t.Fatal("CID modified or reused")
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := p.GenerateConnectionID(); !errors.Is(err, ErrPoolExhausted) {
			t.Fatal("exhausted pool did not fail closed")
		}
	}
	if _, err := NewCIDPool(nil); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	if _, err := NewCIDPool(make([]Token, MaxBatch+1)); !errors.Is(err, ErrOptions) {
		t.Fatal(err)
	}
	if _, err := NewCIDPool([]Token{{1}, {1}}); !errors.Is(err, ErrEntropy) {
		t.Fatal(err)
	}
}

func TestCIDPoolConcurrentConsumption(t *testing.T) {
	tokens := make([]Token, MaxBatch)
	for i := range tokens {
		tokens[i] = Token{byte(i), 1}
	}
	p, err := NewCIDPool(tokens)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan Token, MaxBatch)
	var wg sync.WaitGroup
	for i := 0; i < MaxBatch; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cid, err := p.GenerateConnectionID()
			if err != nil {
				t.Error(err)
				return
			}
			token, err := ParseToken(cid.Bytes())
			if err != nil {
				t.Error(err)
				return
			}
			results <- token
		}()
	}
	wg.Wait()
	close(results)
	seen := make(map[Token]bool)
	for token := range results {
		if seen[token] {
			t.Fatal("token used twice")
		}
		seen[token] = true
	}
	if len(seen) != MaxBatch {
		t.Fatal("lost tokens")
	}
}
