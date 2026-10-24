package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var activeInboundController atomic.Pointer[inboundController]

// The controller outlives individual listener generations. Planned replacements
// must not wake main's fatal-error path as if a listener had failed on its own.
type inboundController struct {
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	current  *inboundSet
	applied  inboundCatalog
	failure  error
	persist  func(inboundCatalog) error
	watchers sync.WaitGroup
}

func startInboundController(parent context.Context, catalog inboundCatalog) (*inboundController, error) {
	ctx, cancel := context.WithCancel(parent)
	running, err := startInboundSet(ctx, catalog)
	if err != nil {
		cancel()
		return nil, err
	}
	c := &inboundController{ctx: ctx, cancel: cancel, applied: catalog}
	c.install(running)
	return c, nil
}

// Caller owns mu, or has not published the controller yet.
func (c *inboundController) install(running *inboundSet) {
	c.current = running
	activeInboundSet.Store(running)
	c.watchers.Add(1)
	go func() {
		defer c.watchers.Done()
		err := running.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.current == running && c.ctx.Err() == nil {
			c.failure = err
			c.cancel()
		}
	}()
}

// Saved settings remain separate from applied settings. If startup fails,
// restore the previous in-memory generation and return a failed application,
// never a successful application of the saved revision.
func (c *inboundController) Apply(candidate inboundCatalog) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil || c.current == nil {
		return false, errors.New("inbound controller is stopped")
	}
	if !candidate.Initialized || candidate.Revision < c.applied.Revision {
		return false, errors.New("invalid or stale inbound candidate")
	}
	var specs []InboundSpec
	for _, record := range candidate.Inbounds {
		if record.identity == nil {
			return false, errors.New("inbound candidate has no identity")
		}
		specs = append(specs, record.Settings)
	}
	if err := validateInboundSet(specs); err != nil {
		return false, err
	}
	if candidate.Revision == c.applied.Revision {
		return false, nil
	}
	previous, old := c.applied, c.current
	c.current = nil
	activeInboundSet.CompareAndSwap(old, nil)
	old.Close()
	running, err := startInboundSet(c.ctx, candidate)
	if err == nil && c.persist != nil {
		if persistErr := c.persist(candidate); persistErr != nil {
			running.Close()
			err = fmt.Errorf("persist applied inbound catalog: %w", persistErr)
		}
	}
	if err == nil {
		c.applied = candidate
		c.install(running)
		return false, nil
	}
	restored, restoreErr := startInboundSet(c.ctx, previous)
	if restoreErr != nil {
		c.failure = fmt.Errorf("inbound apply failed: %w; runtime rollback failed: %v", err, restoreErr)
		c.cancel()
		return false, c.failure
	}
	c.install(restored)
	return true, fmt.Errorf("inbound apply failed; previous runtime restored: %w", err)
}

func (c *inboundController) Wait() error {
	<-c.ctx.Done()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failure != nil {
		return c.failure
	}
	return c.ctx.Err()
}

func (c *inboundController) Close() {
	c.mu.Lock()
	c.cancel()
	if c.current != nil {
		old := c.current
		c.current = nil
		activeInboundSet.CompareAndSwap(old, nil)
		old.Close()
	}
	c.mu.Unlock()
	c.watchers.Wait()
}
