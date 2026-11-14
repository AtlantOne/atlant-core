package wire

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestFairPacerSharesOneBudgetAcrossFlows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := NewFairPacer(1)
		defer p.Close()
		start := time.Now()
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := p.Wait(context.Background(), false, 32768); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if elapsed := time.Since(start); elapsed < time.Second || elapsed > 1100*time.Millisecond {
			t.Fatalf("four streams bypassed shared 1Mbps budget: %v", elapsed)
		}
	})
}

func TestFairPacerPrioritizesSparseWithoutStarvingBulk(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := &FairPacer{rate: 125000, quantum: 1200, high: make(chan paceRequest, 128), normal: make(chan paceRequest, 128), done: make(chan struct{})}
		defer p.Close()
		normal := paceRequest{ctx: context.Background(), bytes: 1200, ready: make(chan struct{}, 1)}
		p.normal <- normal
		high := make([]paceRequest, 16)
		for i := range high {
			high[i] = paceRequest{ctx: context.Background(), bytes: 1200, ready: make(chan struct{}, 1)}
			p.high <- high[i]
		}
		go p.run()
		<-high[0].ready
		select {
		case <-normal.ready:
			t.Fatal("bulk overtook queued interactive traffic")
		default:
		}
		<-normal.ready
		if len(p.high) < 7 {
			t.Fatal("interactive traffic starved bulk beyond weighted turn")
		}
	})
}

func TestFairPacerCancellationAndUnlimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := NewFairPacer(1)
		defer p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		if err := p.Wait(ctx, false, 65536); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wait did not cancel: %v", err)
		}
		if err := p.Wait(context.Background(), true, 20); err != nil {
			t.Fatal(err)
		}
		if NewFairPacer(0) != nil {
			t.Fatal("unlimited mode allocated a scheduler")
		}
		p.Close()
		if err := p.Wait(context.Background(), false, 1); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}
