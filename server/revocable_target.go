package main

import (
	"io"
	"sync"
)

// A kick can race an outbound dial. A target attached after revocation must be
// closed immediately rather than surviving an earlier snapshot of sessions.
type revocableTarget struct {
	mu     sync.Mutex
	closed bool
	target io.Closer
}

func (r *revocableTarget) Attach(target io.Closer) bool {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		target.Close()
		return false
	}
	r.target = target
	r.mu.Unlock()
	return true
}

func (r *revocableTarget) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	target := r.target
	r.target = nil
	r.mu.Unlock()
	if target != nil {
		return target.Close()
	}
	return nil
}
