package main

import (
	"context"
	"errors"
	"testing"
)

func TestAppliedInboundSnapshotSurvivesReopenSeparatelyFromPendingSettings(t *testing.T) {
	store, path := inboundStoreFixture(t)
	ctx := context.Background()
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("first", freeInboundAddress(t))
	record, _, err := store.putInbound(ctx, spec, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	applied, _ := store.readInboundCatalog(ctx)
	if err := store.saveAppliedInboundCatalog(ctx, applied); err != nil {
		t.Fatal(err)
	}
	spec.SNI = "pending.example.com"
	if _, _, err := store.putInbound(ctx, spec, 2, false); err != nil {
		t.Fatal(err)
	}
	store.Close()
	reopened, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, err := reopened.readAppliedInboundCatalog(ctx)
	if err != nil || current.Revision != 2 || current.Inbounds[0].PublicKey != record.PublicKey || current.Inbounds[0].Settings.SNI == spec.SNI {
		t.Fatal("pending settings replaced boot snapshot", err)
	}
	saved, err := reopened.readInboundCatalog(ctx)
	if err != nil || saved.Revision != 3 || saved.Inbounds[0].Settings.SNI != spec.SNI {
		t.Fatal("pending changes lost", err)
	}
	if _, err := reopened.db.Exec(`UPDATE inbound_applied_catalog SET snapshot='{"revision":2,"records":[],"unknown":true}'`); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.readAppliedInboundCatalog(ctx); err == nil {
		t.Fatal("corrupt applied snapshot ignored")
	}
}

func TestInboundControllerAppliedPersistenceFailureRollsRuntimeBack(t *testing.T) {
	c, original := controllerFixture(t)
	c.persist = func(inboundCatalog) error { return errors.New("fixture write failure") }
	candidate := inboundCatalog{Initialized: true, Revision: 2, Inbounds: []inboundRecord{inboundRecordFixture(t, "candidate", freeInboundAddress(t))}}
	if restored, err := c.Apply(candidate); !restored || err == nil {
		t.Fatal("persistence error not rolled back", restored, err)
	}
	assertInboundListening(t, original.Inbounds[0].Settings.Listen)
	if c.ctx.Err() != nil || activeInboundSet.Load().revision != 1 {
		t.Fatal("failed write changed applied state")
	}
}
