package main

import (
	"sync"
	"sync/atomic"
	"testing"
)

type countedTarget struct{ closed atomic.Int32 }

func (c *countedTarget) Close() error { c.closed.Add(1); return nil }

func TestKickClosesTargetAndRefusesLateDial(t *testing.T) {
	var target revocableTarget
	first := &countedTarget{}
	if !target.Attach(first) {
		t.Fatal("initial target rejected")
	}
	target.Close()
	target.Close()
	if first.closed.Load() != 1 {
		t.Fatal("target not closed exactly once")
	}
	late := &countedTarget{}
	if target.Attach(late) || late.closed.Load() != 1 {
		t.Fatal("dial completed after revocation survived")
	}
}

func TestQuotaReservationIsAtomicAndStopsAtLimit(t *testing.T) {
	isolateUsers(t)
	usersDB.Users["alice"] = &userRecord{Name: "alice", Enabled: true, TotalLimit: 100}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if recordUserTraffic("alice", 7, 0) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 14 || usersDB.Users["alice"].UpBytes != 98 {
		t.Fatal("quota exceeded or reservations lost")
	}
	if recordUserTraffic("alice", 3, 0) {
		t.Fatal("oversized next chunk accepted")
	}
}
