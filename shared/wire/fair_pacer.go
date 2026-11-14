package wire

import (
	"context"
	"math"
	"sync"
	"time"
)

type paceRequest struct {
	ctx   context.Context
	bytes int
	ready chan struct{}
}

// FairPacer is an aggregate byte budget, not a congestion controller. Each
// waiter gets at most one short quantum before rejoining its class queue.
// Zero bandwidth is unlimited and has no goroutine or timer overhead.
type FairPacer struct {
	rate         int64
	quantum      int
	high, normal chan paceRequest
	done         chan struct{}
	once         sync.Once
}

func NewFairPacer(mbps uint64) *FairPacer {
	if mbps == 0 {
		return nil
	}
	mbps = min(mbps, uint64(math.MaxInt64/1000000))
	rate := int64(mbps) * 1000000 / 8
	p := &FairPacer{rate: rate, quantum: int(max(1200, min(32768, rate/200))), high: make(chan paceRequest, 128), normal: make(chan paceRequest, 128), done: make(chan struct{})}
	go p.run()
	return p
}

func (p *FairPacer) Close() {
	if p != nil {
		p.once.Do(func() { close(p.done) })
	}
}

func (p *FairPacer) Wait(ctx context.Context, priority bool, n int) error {
	if p == nil || n <= 0 {
		return ctx.Err()
	}
	queue := p.normal
	if priority {
		queue = p.high
	}
	for n > 0 {
		size := min(n, p.quantum)
		r := paceRequest{ctx: ctx, bytes: size, ready: make(chan struct{}, 1)}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return context.Canceled
		case queue <- r:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return context.Canceled
		case <-r.ready:
		}
		n -= size
	}
	return nil
}

func (p *FairPacer) run() {
	next := time.Now()
	priorityRun := 0
	for {
		var r paceRequest
		found := false
		if priorityRun >= 8 {
			select {
			case r = <-p.normal:
				found = true
				priorityRun = 0
			default:
			}
		}
		if !found {
			select {
			case r = <-p.high:
				found = true
				priorityRun++
			default:
			}
		}
		if !found {
			select {
			case <-p.done:
				return
			case r = <-p.high:
				priorityRun++
			case r = <-p.normal:
				priorityRun = 0
			}
		}
		if r.ctx.Err() != nil {
			continue
		}
		if delay := time.Until(next); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-p.done:
				timer.Stop()
				return
			case <-r.ctx.Done():
				timer.Stop()
				continue
			case <-timer.C:
			}
		}
		if r.ctx.Err() != nil {
			continue
		}
		next = time.Now().Add(time.Duration(float64(r.bytes) / float64(p.rate) * float64(time.Second)))
		r.ready <- struct{}{}
	}
}
