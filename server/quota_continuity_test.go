package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func reservedTestBudget() *nodeBudget {
	b := &nodeBudget{grant: quotaID(), capacity: 100, allowed: true, deadline: time.Now().Add(-time.Minute)}
	b.authorization.Store(&quotaAuthorization{allowed: true, reserved: true})
	return b
}

func TestReservedQuotaSurvivesFailedRefreshWithoutResettingUsage(t *testing.T) {
	b := reservedTestBudget()
	b.call = func(context.Context, quotaRequest) (quotaReply, error) {
		return quotaReply{}, errors.New("coordinator unavailable")
	}
	b.mu.Lock()
	err := b.syncLocked(false, 0)
	b.mu.Unlock()
	if err == nil || !b.valid() || !b.consume(30, 20) || !b.consume(50, 0) || b.consume(1, 0) {
		t.Fatal("reserved bytes lost or quota exceeded during coordinator failure")
	}
	if b.up != 80 || b.down != 20 {
		t.Fatal("usage was reset")
	}
}

func TestReservedQuotaDoesNotBlockPacketsBehindSlowRefresh(t *testing.T) {
	b := reservedTestBudget()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.call = func(context.Context, quotaRequest) (quotaReply, error) {
		close(started)
		<-release
		return quotaReply{Grant: b.grant, Capacity: 100, Allowed: true, ReservedAccess: true, ValidSeconds: 6}, nil
	}
	go func() { b.mu.Lock(); _ = b.syncLocked(false, 0); b.mu.Unlock(); close(finished) }()
	<-started
	consumed := make(chan bool, 1)
	go func() { consumed <- b.consume(10, 0) }()
	select {
	case ok := <-consumed:
		if !ok {
			t.Error("reserved packet rejected")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("packet blocked behind quota RPC")
	}
	close(release)
	<-finished
	if b.up != 10 {
		t.Fatal("in-flight traffic accounting overwritten")
	}
}

func TestReservedQuotaCannotSpendAmbiguouslyClosedGrant(t *testing.T) {
	b := reservedTestBudget()
	b.pending = &quotaRequest{Close: true}
	b.call = func(context.Context, quotaRequest) (quotaReply, error) { return quotaReply{}, errors.New("lost reply") }
	if b.consume(1, 0) {
		t.Fatal("spent bytes that may have been returned to coordinator")
	}
}

func TestReservedQuotaExpiryAndExplicitDenialStillRevoke(t *testing.T) {
	b := reservedTestBudget()
	b.authorization.Store(&quotaAuthorization{allowed: true, reserved: true, expiresAt: time.Now().Unix() - 1})
	if b.valid() {
		t.Fatal("absolute subscription expiry ignored")
	}
	b.authorization.Store(&quotaAuthorization{allowed: false, reserved: true})
	if b.valid() {
		t.Fatal("explicit denial ignored")
	}
	b.authorization.Store(&quotaAuthorization{allowed: true, reserved: true})
	b.retired.Store(true)
	if b.valid() {
		t.Fatal("retired binding revived")
	}
}

func TestQuotaRefreshDeadlineAndShutdownCancellation(t *testing.T) {
	b := reservedTestBudget()
	stop, started, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.stop = stop
	b.call = func(ctx context.Context, _ quotaRequest) (quotaReply, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 14*time.Second || time.Until(deadline) > 15*time.Second {
			t.Error("refresh does not have the bounded 15-second deadline")
		}
		close(started)
		<-ctx.Done()
		return quotaReply{}, ctx.Err()
	}
	go func() { b.mu.Lock(); _ = b.syncLocked(false, 0); b.mu.Unlock(); close(finished) }()
	<-started
	close(stop)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel quota RPC")
	}
}
