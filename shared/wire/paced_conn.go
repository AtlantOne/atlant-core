package wire

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type trafficWindow struct {
	started time.Time
	bytes   int
	wasBulk bool
}

// PacedConn preserves packet boundaries when packet is true. Sparse UDP
// receives priority, but sustained high-rate UDP is demoted just like bulk TCP.
type PacedConn struct {
	net.Conn
	read, write          *FairPacer
	ctx                  context.Context
	cancel               context.CancelFunc
	packet               bool
	mu                   sync.Mutex
	rwindow, wwindow     trafficWindow
	rdeadline, wdeadline atomic.Int64
	rwatch, wwatch       DeadlineWatch
	rwait, wwait         map[uint64]context.CancelFunc
	waitID               uint64
	closed               sync.Once
	onClose              func()
}

func PaceConn(conn net.Conn, read, write *FairPacer, packet bool, onClose func()) net.Conn {
	if read == nil && write == nil {
		if onClose != nil {
			onClose()
		}
		return conn
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &PacedConn{Conn: conn, read: read, write: write, packet: packet, ctx: ctx, cancel: cancel, onClose: onClose, rwait: make(map[uint64]context.CancelFunc), wwait: make(map[uint64]context.CancelFunc)}
	c.rwatch.Set(time.Time{}, func() { c.cancelWaiters(true) })
	c.wwatch.Set(time.Time{}, func() { c.cancelWaiters(false) })
	return c
}

func (c *PacedConn) cancelWaiters(read bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := c.wdeadline.Load()
	if read {
		deadline = c.rdeadline.Load()
	}
	if deadline == 0 || time.Now().UnixNano() < deadline {
		return
	}
	waiters := c.wwait
	if read {
		waiters = c.rwait
	}
	for _, cancel := range waiters {
		cancel()
	}
}

func (c *PacedConn) priority(read bool, n int) bool {
	if !c.packet {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	w := &c.wwindow
	if read {
		w = &c.rwindow
	}
	now := time.Now()
	if w.started.IsZero() || now.Sub(w.started) >= 100*time.Millisecond {
		w.wasBulk = !w.started.IsZero() && w.bytes > 32<<10
		w.started = now
		w.bytes = 0
	}
	w.bytes += n
	return !w.wasBulk && w.bytes <= 32<<10
}

func (c *PacedConn) wait(p *FairPacer, read bool, n int) error {
	if p == nil {
		return nil
	}
	deadline := c.wdeadline.Load()
	if read {
		deadline = c.rdeadline.Load()
	}
	if deadline != 0 && time.Now().UnixNano() >= deadline {
		return os.ErrDeadlineExceeded
	}
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	c.mu.Lock()
	c.waitID++
	id := c.waitID
	waiters, watch := c.wwait, &c.wwatch
	if read {
		waiters, watch = c.rwait, &c.rwatch
	}
	waiters[id] = cancel
	c.mu.Unlock()
	watch.Begin()
	defer func() { watch.End(); c.mu.Lock(); delete(waiters, id); c.mu.Unlock() }()
	err := p.Wait(ctx, c.priority(read, n), n)
	if read {
		deadline = c.rdeadline.Load()
	} else {
		deadline = c.wdeadline.Load()
	}
	if err != nil && c.ctx.Err() == nil && deadline != 0 && time.Now().UnixNano() >= deadline {
		return os.ErrDeadlineExceeded
	}
	return err
}

func (c *PacedConn) Read(p []byte) (int, error) {
	if !c.packet && len(p) > 32<<10 {
		p = p[:32<<10]
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		if paceErr := c.wait(c.read, true, n); paceErr != nil {
			// The underlying socket has consumed these bytes. Return them with
			// the error so a deadline cannot silently remove stream contents.
			return n, paceErr
		}
	}
	return n, err
}

func (c *PacedConn) Write(p []byte) (int, error) {
	if c.packet {
		if err := c.wait(c.write, false, len(p)); err != nil {
			return 0, err
		}
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		next := min(len(p), 32<<10)
		if err := c.wait(c.write, false, next); err != nil {
			return total, err
		}
		n, err := c.Conn.Write(p[:next])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n != next {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *PacedConn) Close() error {
	c.closed.Do(func() {
		c.cancel()
		c.rwatch.Stop()
		c.wwatch.Stop()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}
func (c *PacedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
func (c *PacedConn) SetReadDeadline(t time.Time) error {
	var n int64
	if !t.IsZero() {
		n = t.UnixNano()
	}
	c.rdeadline.Store(n)
	c.rwatch.Set(t, func() { c.cancelWaiters(true) })
	return c.Conn.SetReadDeadline(t)
}
func (c *PacedConn) SetWriteDeadline(t time.Time) error {
	var n int64
	if !t.IsZero() {
		n = t.UnixNano()
	}
	c.wdeadline.Store(n)
	c.wwatch.Set(t, func() { c.cancelWaiters(false) })
	return c.Conn.SetWriteDeadline(t)
}
func (c *PacedConn) SetDeadline(t time.Time) error {
	err := c.SetReadDeadline(t)
	other := c.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return other
}
