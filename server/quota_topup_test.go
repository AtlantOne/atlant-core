package main

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestQuotaTopUpLostReplyKeepsConfirmedCredit(t *testing.T) {
	s, _ := quotaFixture(t, 32<<20)
	b := testBudget(s.ID, "local")
	if !b.consume(1, 0) {
		t.Fatal("Initial grant missing")
	}
	grant, capacity := b.grant, b.capacity
	original := b.call
	lost := true
	b.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		reply, err := original(ctx, r)
		if err == nil && r.Want > 0 && lost {
			lost = false
			return quotaReply{}, io.ErrUnexpectedEOF
		}
		return reply, err
	}
	b.mu.Lock()
	err := b.syncLocked(false, quotaChunk)
	b.mu.Unlock()
	if err == nil || b.capacity != capacity || !b.consume(10, 0) {
		t.Fatal("Lost reply changed confirmed credit or blocked remaining bytes")
	}
	b.mu.Lock()
	err = b.syncLocked(false, 0)
	b.mu.Unlock()
	if err != nil || b.capacity != capacity+quotaChunk || b.up != 11 || b.grant != grant {
		t.Fatal("Top-up replay lost usage or allocated twice", err)
	}
	b.mu.Lock()
	err = b.syncLocked(true, 0)
	b.mu.Unlock()
	q, readErr := readQuota(context.Background(), currentUsersStore.db, s.ID)
	if err != nil || readErr != nil || q.Up != 11 || q.Reserved != 0 {
		t.Fatal(q, err, readErr)
	}
}

func TestQuotaTopUpBoundsOutstandingReservation(t *testing.T) {
	s, _ := quotaFixture(t, 256<<20)
	b := testBudget(s.ID, "local")
	if !b.consume(1, 0) {
		t.Fatal("Initial grant missing")
	}
	for i := 0; i < 3; i++ {
		b.mu.Lock()
		err := b.syncLocked(false, quotaMaxReservation)
		b.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if b.capacity-b.up-b.down > quotaMaxReservation {
			t.Fatal("Outstanding credit exceeded bound")
		}
	}
}

func TestQuotaTopUpRetainsGrantAndIsIdempotent(t *testing.T) {
	s, _ := quotaFixture(t, 10<<20)
	now := time.Now()
	r := quotaRequest{ID: quotaID(), Session: quotaID(), Subscription: s.ID, Want: quotaChunk, IssuedAt: now.Unix()}
	first, err := processQuota(context.Background(), currentUsersStore.db, "local", r, now)
	if err != nil || !first.CanTopUp {
		t.Fatal(first, err)
	}
	r.ID = quotaID()
	r.Grant = first.Grant
	r.Up = 1 << 20
	r.Want = 6 << 20
	second, err := processQuota(context.Background(), currentUsersStore.db, "local", r, now)
	if err != nil || second.Grant != first.Grant || second.Capacity != 10<<20 {
		t.Fatal(second, err)
	}
	again, err := processQuota(context.Background(), currentUsersStore.db, "local", r, now)
	if err != nil || again != second {
		t.Fatal("Top-up replay changed allocation", again, err)
	}
	q, err := readQuota(context.Background(), currentUsersStore.db, s.ID)
	if err != nil || q.Up != 1<<20 || q.Reserved != 9<<20 {
		t.Fatal(q, err)
	}
}

func TestQuotaTopUpDoesNotBlockOtherFlows(t *testing.T) {
	b := reservedTestBudget()
	b.up = 95
	b.canTopUp = true
	grant := b.grant
	entered, release := make(chan struct{}), make(chan struct{})
	b.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		if r.Close {
			t.Error("Refill closed the active grant")
		}
		close(entered)
		<-release
		return quotaReply{Grant: grant, Capacity: 200, Allowed: true, ReservedAccess: true, ValidSeconds: 6, CanTopUp: true}, nil
	}
	transfer := make(chan bool, 1)
	go func() { transfer <- b.consume(10, 0) }()
	<-entered
	dns := make(chan bool, 1)
	go func() { dns <- b.consume(1, 0) }()
	select {
	case ok := <-dns:
		if !ok {
			t.Error("Confirmed bytes rejected")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Other flow waited for refill")
	}
	close(release)
	if !<-transfer {
		t.Fatal("Transfer rejected after refill")
	}
	if b.up != 106 || b.grant != grant {
		t.Fatal("In-flight usage or grant changed", b.up)
	}
}

func TestQuotaPrefetchRunsOutsidePacketPath(t *testing.T) {
	b := reservedTestBudget()
	b.capacity = quotaChunk
	b.canTopUp = true
	stop := make(chan struct{})
	b.stop = stop
	entered, release := make(chan struct{}), make(chan struct{})
	grant := b.grant
	b.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return quotaReply{}, ctx.Err()
		}
		return quotaReply{Grant: grant, Capacity: quotaChunk + r.Want, Allowed: true, ReservedAccess: true, ValidSeconds: 6, CanTopUp: true}, nil
	}
	defer func() { close(stop); b.prefetchWG.Wait() }()
	if !b.consume(1, 0) {
		t.Fatal("Initial packet rejected")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("Prefetch was not started")
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- b.consume(1024, 0) }()
	select {
	case ok := <-accepted:
		if !ok {
			t.Error("Reserved bytes rejected")
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Packet blocked on prefetch")
	}
	close(release)
	b.prefetchWG.Wait()
	if b.up != 1025 || b.capacity <= quotaChunk {
		t.Fatal("Prefetch lost usage or failed to extend", b.up, b.capacity)
	}
}
