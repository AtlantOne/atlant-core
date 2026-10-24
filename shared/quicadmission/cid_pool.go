package quicadmission

import (
	"github.com/quic-go/quic-go"
	"sync"
)

// CIDPool consumes a fresh authenticated batch in memory, once per connection.
// It never replenishes itself or switches to legacy CIDs. Reusing a batch in
// another pool is invalid even if the server rejects the resulting attempt.
type CIDPool struct {
	mu     sync.Mutex
	tokens []Token
}

func NewCIDPool(tokens []Token) (*CIDPool, error) {
	if len(tokens) < 1 || len(tokens) > MaxBatch {
		return nil, ErrOptions
	}
	seen := make(map[Token]struct{}, len(tokens))
	for _, token := range tokens {
		if _, ok := seen[token]; ok {
			return nil, ErrEntropy
		}
		seen[token] = struct{}{}
	}
	return &CIDPool{tokens: append([]Token(nil), tokens...)}, nil
}
func (*CIDPool) ConnectionIDLen() int { return TokenSize }
func (p *CIDPool) GenerateConnectionID() (quic.ConnectionID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.tokens) == 0 {
		return quic.ConnectionID{}, ErrPoolExhausted
	}
	token := p.tokens[0]
	p.tokens[0] = Token{}
	p.tokens = p.tokens[1:]
	return quic.ConnectionIDFromBytes(token[:]), nil
}

var _ quic.ConnectionIDGenerator = (*CIDPool)(nil)
