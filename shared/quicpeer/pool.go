package quicpeer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultBulkCarriers = 4
const MaxBulkCarriers = 8

type Carrier struct {
	Conn      ClientConn
	Resources io.Closer
	once      sync.Once
}

func (c *Carrier) Close() error {
	c.once.Do(func() {
		if c.Conn != nil {
			_ = c.Conn.CloseWithError(0, "carrier retired")
		}
		if c.Resources != nil {
			_ = c.Resources.Close()
		}
	})
	return nil
}

type CarrierDial func(context.Context) (*Carrier, error)

type PoolStats struct{ MinimumRTT, SmoothedRTT time.Duration }

type poolEntry struct {
	carrier      *Carrier
	active       int
	pending      atomic.Int64
	writeWait    atomic.Int64
	wait         chan struct{}
	err          error
	retry        time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	timer        *time.Timer
	idleSequence uint64
	retired      bool
}

// StreamPool owns bulk carriers only. Interactive DATAGRAM/DNS traffic uses
// the client's primary carrier and cannot be assigned a bulk stream here.
// Its zero value is ready to use. A key is a private profile digest, never a CID.
type StreamPool struct {
	mu      sync.Mutex
	key     [32]byte
	entries []*poolEntry
	// IdleTimeout is optional and must be set before first use.
	IdleTimeout time.Duration
}

type CarrierLease struct {
	pool  *StreamPool
	entry *poolEntry
	Conn  ClientConn
	once  sync.Once
}

func (l *CarrierLease) Pending(n int) {
	if l != nil {
		l.entry.pending.Add(int64(n))
	}
}

func (l *CarrierLease) ObserveWrite(elapsed time.Duration) {
	old := l.entry.writeWait.Load()
	l.entry.writeWait.Store((old*7 + int64(elapsed)) / 8)
}

func (l *CarrierLease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		p, e := l.pool, l.entry
		p.mu.Lock()
		e.active--
		if e.active == 0 && !e.retired {
			e.idleSequence++
			sequence := e.idleSequence
			idle := p.IdleTimeout
			if idle <= 0 {
				var random [2]byte
				_, _ = rand.Read(random[:])
				idle = time.Duration(45+binary.BigEndian.Uint16(random[:])%46) * time.Second
			}
			e.timer = time.AfterFunc(idle, func() { p.expire(e, sequence) })
		}
		p.mu.Unlock()
	})
}

func (p *StreamPool) expire(e *poolEntry, sequence uint64) {
	p.mu.Lock()
	if e.retired || e.active != 0 || e.wait != nil || e.idleSequence != sequence {
		p.mu.Unlock()
		return
	}
	resource := p.removeLocked(e)
	p.mu.Unlock()
	if resource != nil {
		_ = resource.Close()
	}
}

func (p *StreamPool) removeLocked(e *poolEntry) *Carrier {
	e.retired = true
	e.cancel()
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	for i, current := range p.entries {
		if current == e {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			break
		}
	}
	return e.carrier
}

func (p *StreamPool) Reset() {
	p.mu.Lock()
	var resources []*Carrier
	for len(p.entries) > 0 {
		if c := p.removeLocked(p.entries[len(p.entries)-1]); c != nil {
			resources = append(resources, c)
		}
	}
	p.key = [32]byte{}
	p.mu.Unlock()
	for _, c := range resources {
		_ = c.Close()
	}
}

// Acquire grows on concurrent demand, reuses idle carriers, and at the limit
// chooses the least queued carrier. Dialing never holds the pool mutex.
func (p *StreamPool) Acquire(ctx context.Context, key [32]byte, limit int, dial CarrierDial) (*CarrierLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = DefaultBulkCarriers
	}
	limit = min(limit, MaxBulkCarriers)
	p.mu.Lock()
	var closing []*Carrier
	if p.key != key {
		for len(p.entries) > 0 {
			if c := p.removeLocked(p.entries[len(p.entries)-1]); c != nil {
				closing = append(closing, c)
			}
		}
		p.key = key
	}
	var best *poolEntry
	pressure := false
	now := time.Now()
	for i := 0; i < len(p.entries); {
		e := p.entries[i]
		if e.ctx.Err() != nil || e.carrier != nil && e.carrier.Conn.Context().Err() != nil {
			if c := p.removeLocked(e); c != nil {
				closing = append(closing, c)
			}
			continue
		}
		if e.carrier != nil {
			if source, ok := e.carrier.Conn.(interface{ PoolStats() PoolStats }); ok {
				s := source.PoolStats()
				if s.MinimumRTT > 0 && s.SmoothedRTT > s.MinimumRTT+max(15*time.Millisecond, s.MinimumRTT/4) {
					pressure = true
				}
			}
		}
		cooling := e.carrier == nil && now.Before(e.retry)
		bestCooling := best != nil && best.carrier == nil && now.Before(best.retry)
		if best == nil || bestCooling && !cooling || bestCooling == cooling && (e.active < best.active || e.active == best.active &&
			(e.pending.Load() < best.pending.Load() || e.pending.Load() == best.pending.Load() && e.writeWait.Load() < best.writeWait.Load())) {
			best = e
		}
		i++
	}
	// Keep one additional lane available for isolation. Beyond that, avoid
	// opening more congestion windows while existing lanes already queue up.
	if best == nil || best.active > 0 && len(p.entries) < limit && (!pressure || len(p.entries) < 2) {
		life, cancel := context.WithCancel(ctx)
		best = &poolEntry{ctx: life, cancel: cancel}
		p.entries = append(p.entries, best)
		entry := best
		context.AfterFunc(life, func() {
			p.mu.Lock()
			var resource *Carrier
			if !entry.retired {
				resource = p.removeLocked(entry)
			}
			p.mu.Unlock()
			if resource != nil {
				_ = resource.Close()
			}
		})
	}
	best.active++
	best.idleSequence++
	if best.timer != nil {
		best.timer.Stop()
		best.timer = nil
	}
	l := &CarrierLease{pool: p, entry: best}
	p.mu.Unlock()
	for _, c := range closing {
		_ = c.Close()
	}
	conn, err := p.get(ctx, best, dial)
	if err != nil {
		l.Release()
		return nil, err
	}
	l.Conn = conn
	return l, nil
}

func (p *StreamPool) get(ctx context.Context, e *poolEntry, dial CarrierDial) (ClientConn, error) {
	for {
		p.mu.Lock()
		if e.retired || e.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, context.Canceled
		}
		if e.carrier != nil {
			c := e.carrier.Conn
			p.mu.Unlock()
			return c, nil
		}
		if e.wait != nil {
			wait := e.wait
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-wait:
				continue
			}
		}
		if time.Now().Before(e.retry) {
			err := e.err
			p.mu.Unlock()
			return nil, err
		}
		wait := make(chan struct{})
		e.wait = wait
		p.mu.Unlock()
		dialCtx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
		c, err := dial(dialCtx)
		cancel()
		if err == nil && (c == nil || c.Conn == nil) {
			err = errors.New("QUIC dial returned no carrier")
		}
		p.mu.Lock()
		if e.retired || e.ctx.Err() != nil {
			err = context.Canceled
		}
		if err == nil {
			e.carrier = c
		} else {
			e.err = err
			e.retry = time.Now().Add(time.Second)
		}
		e.wait = nil
		close(wait)
		p.mu.Unlock()
		if err != nil {
			if c != nil {
				_ = c.Close()
			}
			return nil, err
		}
		context.AfterFunc(c.Conn.Context(), func() {
			p.mu.Lock()
			if !e.retired {
				p.removeLocked(e)
			}
			p.mu.Unlock()
			_ = c.Close()
		})
		return c.Conn, nil
	}
}
