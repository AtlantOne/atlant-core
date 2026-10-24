package main

import (
	"testing"
	"time"
)

func TestPacerDoesNotSkipLongWaitOrCreditItTwice(t *testing.T) {
	p := NewBrutalPacer(1)
	start := time.Now()
	p.Pace(65536)
	if time.Since(start) < 480*time.Millisecond {
		t.Fatal("rate limit skipped a wait longer than 100ms")
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
