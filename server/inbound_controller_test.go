package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func controllerFixture(t *testing.T) (*inboundController, inboundCatalog) {
	t.Helper()
	previous := activeInboundSet.Load()
	catalog := inboundCatalog{Initialized: true, Revision: 1, Inbounds: []inboundRecord{inboundRecordFixture(t, "first", freeInboundAddress(t))}}
	c, err := startInboundController(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); activeInboundSet.Store(previous) })
	return c, catalog
}

func assertInboundListening(t *testing.T, address string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal("listener unavailable", err)
	}
	conn.Close()
}

func TestInboundControllerAppliesGenerationWithoutStoppingSupervisor(t *testing.T) {
	c, original := controllerFixture(t)
	candidate := inboundCatalog{Initialized: true, Revision: 2, Inbounds: []inboundRecord{inboundRecordFixture(t, "second", freeInboundAddress(t))}}
	for i := 0; i < 4; i++ {
		candidate.Revision = int64(i + 2)
		if restored, err := c.Apply(candidate); restored || err != nil {
			t.Fatal(restored, err)
		}
		assertInboundListening(t, candidate.Inbounds[0].Settings.Listen)
		if c.ctx.Err() != nil || activeInboundSet.Load().revision != candidate.Revision {
			t.Fatal("planned stop killed supervisor")
		}
	}
	old, err := net.Listen("tcp", original.Inbounds[0].Settings.Listen)
	if err != nil {
		t.Fatal("old listener not released", err)
	}
	old.Close()
	if _, err := c.Apply(original); err == nil {
		t.Fatal("stale revision accepted")
	}
}

func TestInboundControllerFailedBindRestoresPreviousRuntime(t *testing.T) {
	c, original := controllerFixture(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	candidate := inboundCatalog{Initialized: true, Revision: 2, Inbounds: []inboundRecord{inboundRecordFixture(t, "blocked", occupied.Addr().String())}}
	if restored, err := c.Apply(candidate); !restored || err == nil {
		t.Fatal("failed bind not reported with rollback", restored, err)
	}
	assertInboundListening(t, original.Inbounds[0].Settings.Listen)
	if c.ctx.Err() != nil || activeInboundSet.Load().revision != 1 {
		t.Fatal("failed candidate advertised as active")
	}
	occupied.Close()
	if restored, err := c.Apply(candidate); restored || err != nil {
		t.Fatal("recovery retry failed", restored, err)
	}
	assertInboundListening(t, candidate.Inbounds[0].Settings.Listen)
}

func TestInboundControllerUnexpectedFailureStillStopsSupervisor(t *testing.T) {
	c, _ := controllerFixture(t)
	c.current.bindings[0].tcp.Close()
	select {
	case <-c.ctx.Done():
		if c.Wait() == nil {
			t.Fatal("runtime failure lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("unexpected listener failure was ignored")
	}
}

func TestInboundControllerReportsFatalRollbackFailure(t *testing.T) {
	c, original := controllerFixture(t)
	var occupied net.Listener
	c.persist = func(inboundCatalog) error {
		var err error
		occupied, err = net.Listen("tcp", original.Inbounds[0].Settings.Listen)
		if err != nil {
			t.Fatal(err)
		}
		return errors.New("fixture persistence failure after old port was taken")
	}
	defer func() {
		if occupied != nil {
			occupied.Close()
		}
	}()
	candidate := inboundCatalog{Initialized: true, Revision: 2, Inbounds: []inboundRecord{inboundRecordFixture(t, "candidate", freeInboundAddress(t))}}
	if restored, err := c.Apply(candidate); restored || err == nil {
		t.Fatal("failed rollback advertised as restored", restored, err)
	}
	if c.ctx.Err() == nil || c.Wait() == nil || activeInboundSet.Load() != nil {
		t.Fatal("fatal rollback left a healthy runtime claim")
	}
}
