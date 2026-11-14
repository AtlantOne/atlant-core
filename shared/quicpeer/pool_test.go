package quicpeer

import (
	"context"
	"errors"
	quic "github.com/quic-go/quic-go"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type poolTestConn struct {
	ClientConn
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Int32
	stats  PoolStats
}

func (c *poolTestConn) PoolStats() PoolStats { return c.stats }

func (c *poolTestConn) Context() context.Context { return c.ctx }
func (c *poolTestConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closed.Add(1)
	c.cancel()
	return nil
}

type poolTestResource struct{ closed atomic.Int32 }

func (c *poolTestResource) Close() error { c.closed.Add(1); return nil }

func poolTestDial(counter *atomic.Int32) CarrierDial {
	return func(context.Context) (*Carrier, error) {
		counter.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		return &Carrier{Conn: &poolTestConn{ctx: ctx, cancel: cancel}, Resources: &poolTestResource{}}, nil
	}
}

func TestBulkPoolUsesHealthyBusyCarrierDuringOtherCarrierCooldown(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	key := [32]byte{41}
	healthy, err := p.Acquire(context.Background(), key, 2, poolTestDial(&dials))
	if err != nil {
		t.Fatal(err)
	}
	defer healthy.Release()
	_, err = p.Acquire(context.Background(), key, 2, func(context.Context) (*Carrier, error) {
		return nil, errors.New("temporary dial failure")
	})
	if err == nil {
		t.Fatal("expected second carrier failure")
	}
	next, err := p.Acquire(context.Background(), key, 2, poolTestDial(&dials))
	if err != nil {
		t.Fatalf("healthy carrier was ignored: %v", err)
	}
	defer next.Release()
	if next.Conn != healthy.Conn || dials.Load() != 1 {
		t.Fatal("did not reuse healthy carrier")
	}
}

func TestBulkPoolBoundsGrowthAndReusesIdle(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	key := [32]byte{1}
	var leases []*CarrierLease
	for i := 0; i < 12; i++ {
		l, err := p.Acquire(context.Background(), key, 4, poolTestDial(&dials))
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if dials.Load() != 4 {
		t.Fatalf("unbounded or missing growth: %d", dials.Load())
	}
	for _, l := range leases {
		l.Release()
		l.Release()
	}
	l, err := p.Acquire(context.Background(), key, 4, poolTestDial(&dials))
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	if dials.Load() != 4 {
		t.Fatal("idle carrier was not reused")
	}
}

func TestBulkPoolLeastQueuedAndReleaseOnce(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	a, _ := p.Acquire(context.Background(), [32]byte{1}, 2, poolTestDial(&dials))
	b, _ := p.Acquire(context.Background(), [32]byte{1}, 2, poolTestDial(&dials))
	a.Pending(64000)
	c, err := p.Acquire(context.Background(), [32]byte{1}, 2, poolTestDial(&dials))
	if err != nil {
		t.Fatal(err)
	}
	if c.entry != b.entry {
		t.Fatal("new stream queued behind congested carrier")
	}
	a.Pending(-64000)
	a.Release()
	b.Release()
	c.Release()
}

func TestBulkPoolWaitCancellationAndResetDuringDial(t *testing.T) {
	var p StreamPool
	started, release := make(chan struct{}), make(chan struct{})
	var dials atomic.Int32
	dial := func(ctx context.Context) (*Carrier, error) {
		close(started)
		<-release
		return poolTestDial(&dials)(ctx)
	}
	first := make(chan error, 1)
	go func() { _, err := p.Acquire(context.Background(), [32]byte{1}, 1, dial); first <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(ctx, [32]byte{1}, 1, dial); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait did not cancel: %v", err)
	}
	p.Reset()
	close(release)
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("stale dial survived reset: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) != 0 {
		t.Fatal("reset left a stale carrier")
	}
}

func TestBulkPoolConcurrentSingleFlight(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := p.Acquire(context.Background(), [32]byte{1}, 1, poolTestDial(&dials))
			if err != nil {
				t.Error(err)
				return
			}
			l.Release()
		}()
	}
	wg.Wait()
	if dials.Load() != 1 {
		t.Fatalf("dial storm: %d", dials.Load())
	}
}

func TestBulkPoolExpiresIdleAndSessionCancellation(t *testing.T) {
	for _, cancelSession := range []bool{false, true} {
		p := StreamPool{IdleTimeout: 20 * time.Millisecond}
		ctx, cancel := context.WithCancel(context.Background())
		var dials atomic.Int32
		l, err := p.Acquire(ctx, [32]byte{1}, 4, poolTestDial(&dials))
		if err != nil {
			t.Fatal(err)
		}
		resource := l.entry.carrier.Resources.(*poolTestResource)
		if cancelSession {
			cancel()
		} else {
			l.Release()
		}
		end := time.Now().Add(time.Second)
		for resource.closed.Load() == 0 && time.Now().Before(end) {
			time.Sleep(time.Millisecond)
		}
		if resource.closed.Load() != 1 {
			t.Fatal("idle/cancelled carrier leaked")
		}
		l.Release()
		p.Reset()
		cancel()
		if resource.closed.Load() != 1 {
			t.Fatal("resources closed multiple times")
		}
	}
}

func TestBulkPoolProfileIsolation(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	a, _ := p.Acquire(context.Background(), [32]byte{1}, 4, poolTestDial(&dials))
	b, err := p.Acquire(context.Background(), [32]byte{2}, 4, poolTestDial(&dials))
	if err != nil {
		t.Fatal(err)
	}
	if a.entry.carrier.Resources.(*poolTestResource).closed.Load() != 1 || a.Conn == b.Conn {
		t.Fatal("profile reused old credentials")
	}
	a.Release()
	b.Release()
}

func TestBulkPoolDoesNotGrowIntoMeasuredQueuePressure(t *testing.T) {
	var p StreamPool
	defer p.Reset()
	var dials atomic.Int32
	dial := func(ctx context.Context) (*Carrier, error) {
		c, err := poolTestDial(&dials)(ctx)
		c.Conn.(*poolTestConn).stats = PoolStats{MinimumRTT: 20 * time.Millisecond, SmoothedRTT: 100 * time.Millisecond}
		return c, err
	}
	var leases []*CarrierLease
	for i := 0; i < 6; i++ {
		l, err := p.Acquire(context.Background(), [32]byte{1}, 4, dial)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if dials.Load() != 2 {
		t.Fatalf("pool grew despite high queue delay: %d", dials.Load())
	}
	for _, l := range leases {
		l.Release()
	}
}
