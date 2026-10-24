package main

import (
	"testing"
	"time"
)

func TestPacerDoesNotCapDebtWait(t *testing.T) {
	p := NewBrutalPacer(1)
	start := time.Now()
	p.Pace(131072)
	if time.Since(start) < time.Second {
		t.Fatal("rate limit clipped a required wait to 500ms")
	}
	start = time.Now()
	p.Pace(16384)
	if time.Since(start) < 120*time.Millisecond {
		t.Fatal("previous wait was credited as new burst capacity")
	}
	if NewBrutalPacer(0) != nil {
		t.Fatal("unlimited rate changed")
	}
}
