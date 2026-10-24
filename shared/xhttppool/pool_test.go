package xhttppool

import (
	"sync"
	"testing"

	"golang.org/x/net/http2"
)

func factory() *http2.Transport { return &http2.Transport{} }

func TestSeparatesActiveStreamsAndReusesIdleCarrier(t *testing.T) {
	var pool Pool
	key := Key("test")
	a, _ := pool.Acquire(key, factory)
	b, _ := pool.Acquire(key, factory)
	if a.Transport() == b.Transport() {
		t.Fatal("active streams shared a carrier despite spare capacity")
	}
	a.Release()
	a.Release()
	c, _ := pool.Acquire(key, factory)
	if a.Transport() != c.Transport() {
		t.Fatal("idle authenticated carrier was not reused")
	}
	b.Release()
	c.Release()
	pool.Reset()
}

func TestBoundedAndChoosesLessBusyCarrier(t *testing.T) {
	var pool Pool
	var leases []*Lease
	key := Key("test")
	for range MaxCarriers {
		lease, _ := pool.Acquire(key, factory)
		leases = append(leases, lease)
	}
	for _, lease := range leases[:MaxCarriers-1] {
		lease.Pending(65536)
	}
	next, _ := pool.Acquire(key, factory)
	if next.Transport() != leases[MaxCarriers-1].Transport() {
		t.Fatal("pending bytes ignored")
	}
	if len(pool.entries) != MaxCarriers {
		t.Fatal("unbounded carrier count")
	}
	for _, lease := range leases {
		lease.Release()
	}
	next.Release()
	pool.Reset()
}

func TestConcurrentResetAndRelease(t *testing.T) {
	var pool Pool
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			lease, err := pool.Acquire(Key("same"), factory)
			if err != nil {
				t.Error(err)
				return
			}
			lease.Pending(123)
			lease.Pending(-123)
			lease.Release()
		})
	}
	pool.Reset()
	wg.Wait()
	pool.Reset()
}

func TestDoesNotReuseAnotherProfilesCredentials(t *testing.T) {
	var pool Pool
	a, _ := pool.Acquire(Key("server", "user-a"), factory)
	b, _ := pool.Acquire(Key("server", "user-b"), factory)
	if a.Transport() == b.Transport() {
		t.Fatal("profiles shared a carrier")
	}
	a.Release()
	b.Release()
	pool.Reset()
}
