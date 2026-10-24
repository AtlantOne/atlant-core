package wire

import (
	"net"
	"testing"
	"time"
)

func TestDeadlineWatchInterruptsAnAlreadyBlockedRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var watch DeadlineWatch
	defer watch.Stop()
	done := make(chan error, 1)
	go func() { _, err := a.Read(make([]byte, 1)); done <- err }()
	watch.Set(time.Now().Add(20*time.Millisecond), func() { a.Close() })
	watch.Begin()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected interrupted read")
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt read")
	}
}

func TestDeadlineWatchCanBeCleared(t *testing.T) {
	var watch DeadlineWatch
	defer watch.Stop()
	fired := make(chan struct{}, 1)
	watch.Set(time.Now().Add(20*time.Millisecond), func() { fired <- struct{}{} })
	watch.Begin()
	watch.Set(time.Time{}, nil)
	select {
	case <-fired:
		t.Fatal("cleared deadline fired")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestIdleWriteDeadlineDoesNotInterruptDownload(t *testing.T) {
	var watch DeadlineWatch
	defer watch.Stop()
	fired := make(chan struct{}, 1)
	watch.Set(time.Now().Add(20*time.Millisecond), func() { fired <- struct{}{} })
	watch.Begin()
	watch.End()
	select {
	case <-fired:
		t.Fatal("finished write cancelled active download")
	case <-time.After(50 * time.Millisecond):
	}
}
