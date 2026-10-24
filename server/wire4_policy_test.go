package main

import "testing"

func TestNewServerDefaultsToStrictTicketlessWire6(t *testing.T) {
	config := DefaultConfig()
	if config.WireVersion != 6 || config.LegacyWire {
		t.Fatal("new deployment enables legacy admission implicitly")
	}
}
