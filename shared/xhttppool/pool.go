// Package xhttppool keeps interactive streams off busy HTTP/2 carriers when
// capacity is available. Leases last for the full duplex stream, not just its
// request headers or upload half.
package xhttppool

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const MaxCarriers = 8

var ErrBusy = errors.New("XHTTP carrier pool is occupied by another profile")

type carrier struct {
	key       [32]byte
	transport *http2.Transport
	active    int
	pending   atomic.Int64
	lastUsed  time.Time
	retired   bool
}

type Pool struct {
	mu      sync.Mutex
	entries []*carrier
}

// Key is an in-memory identity digest, never a loggable copy of a profile key.
func Key(parts ...string) [32]byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

type Lease struct {
	pool  *Pool
	entry *carrier
	once  sync.Once
}

func (p *Pool) Acquire(key [32]byte, create func() *http2.Transport) (*Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	kept := p.entries[:0]
	for _, entry := range p.entries {
		if entry.active == 0 && (entry.key != key || now.Sub(entry.lastUsed) > 90*time.Second) {
			entry.retired = true
			entry.transport.CloseIdleConnections()
			continue
		}
		kept = append(kept, entry)
	}
	p.entries = kept
	var best *carrier
	for _, entry := range p.entries {
		if entry.key != key {
			continue
		}
		if best == nil || entry.active < best.active || entry.active == best.active && entry.pending.Load() < best.pending.Load() {
			best = entry
		}
	}
	// A new logical stream should not sit behind a saturated upload while an
	// independent carrier can still be opened. Do not create an unbounded pool.
	if (best == nil || best.active > 0) && len(p.entries) < MaxCarriers {
		best = &carrier{key: key, transport: create(), lastUsed: now}
		p.entries = append(p.entries, best)
	}
	if best == nil {
		return nil, ErrBusy
	}
	best.active++
	return &Lease{pool: p, entry: best}, nil
}

func (l *Lease) Transport() *http2.Transport { return l.entry.transport }
func (l *Lease) Pending(n int) {
	if l != nil {
		l.entry.pending.Add(int64(n))
	}
}
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.pool.mu.Lock()
		defer l.pool.mu.Unlock()
		l.entry.active--
		l.entry.lastUsed = time.Now()
		if l.entry.retired && l.entry.active == 0 {
			l.entry.transport.CloseIdleConnections()
		}
	})
}

func (p *Pool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		entry.retired = true
		entry.transport.CloseIdleConnections()
	}
	p.entries = nil
}
