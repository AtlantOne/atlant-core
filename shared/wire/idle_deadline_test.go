package wire

import (
	"testing"
	"time"
)

func TestIdleDeadlineDoesNotExtendTimeout(t *testing.T) {
	var d IdleDeadline
	now := time.Unix(100, 0)
	calls := 0
	var last time.Time
	set := func(v time.Time) error { calls++; last = v; return nil }
	for i := range 1000 {
		at := now.Add(time.Duration(i) * time.Millisecond)
		if e := d.Update(at, 120*time.Second, set); e != nil {
			t.Fatal(e)
		}
	}
	if calls != 1 || !last.Equal(now.Add(120*time.Second)) {
		t.Fatal("redundant deadline resets")
	}
	_ = d.Update(now.Add(time.Second), 120*time.Second, set)
	if calls != 2 || !last.Equal(now.Add(121*time.Second)) {
		t.Fatal("deadline not refreshed")
	}
}
