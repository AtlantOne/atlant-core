package main

import (
	"atlant.local/protocol/wire"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestInboundBandwidthIsSharedAcrossCarriers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := DefaultConfig()
		c.InboundID = "bandwidth-test"
		c.UpMbps = 1
		c.DownMbps = 1
		id, releaseTCP := acquireInboundBandwidth(c)
		defer releaseTCP()
		_, releaseQUIC := acquireInboundBandwidth(c)
		defer releaseQUIC()
		var wg sync.WaitGroup
		started := time.Now()
		for i := 0; i < 4; i++ {
			conn := paceServerTarget(&performanceConn{}, false, id)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				if _, err := conn.Write(make([]byte, 32768)); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if elapsed := time.Since(started); elapsed < time.Second || elapsed > 1100*time.Millisecond {
			t.Fatalf("parallel carriers multiplied the inbound rate: %v", elapsed)
		}
		releaseTCP()
		releaseQUIC()
		bandwidthState.Lock()
		_, remains := bandwidthState.entries[id]
		bandwidthState.Unlock()
		if remains {
			t.Fatal("retired inbound kept limiter goroutines alive")
		}
	})
}

func TestRemovingBandwidthLimitAffectsNewTargets(t *testing.T) {
	c := DefaultConfig()
	c.InboundID = "bandwidth-remove-test"
	c.UpMbps = 1
	id, release := acquireInboundBandwidth(c)
	defer release()
	limited := paceServerTarget(&performanceConn{}, false, id)
	defer limited.Close()
	if _, ok := limited.(*wire.PacedConn); !ok {
		t.Fatal("limit not installed")
	}
	next := *c
	next.UpMbps = 0
	_, releaseNext := acquireInboundBandwidth(&next)
	defer releaseNext()
	raw := &performanceConn{}
	if paceServerTarget(raw, false, id) != raw {
		t.Fatal("removed bandwidth limit was still applied")
	}
}

func TestInboundSpeedtestSharesDownloadBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := DefaultConfig()
		c.InboundID = "bandwidth-speedtest"
		c.UpMbps = 1
		id, release := acquireInboundBandwidth(c)
		defer release()
		var wg sync.WaitGroup
		started := time.Now()
		for i := 0; i < 4; i++ {
			conn := paceInboundStream(&performanceConn{}, id)
			wg.Go(func() {
				defer conn.Close()
				if _, err := conn.Write(make([]byte, 32768)); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if elapsed := time.Since(started); elapsed < time.Second || elapsed > 1100*time.Millisecond {
			t.Fatalf("speedtest bypassed shared downlink budget: %v", elapsed)
		}
	})
}
