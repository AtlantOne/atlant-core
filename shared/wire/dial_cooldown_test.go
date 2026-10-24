package wire

import (
	"errors"
	"testing"
	"time"
)

func TestDialCooldownSharesFailureAndAllowsRecovery(t *testing.T) {
	var d DialCooldown
	now := time.Now()
	failure := errors.New("handshake timeout")
	d.Record(failure, now)
	for i := 0; i < 100; i++ {
		if d.RetryError(now.Add(500*time.Millisecond)) != failure {
			t.Fatal("waiter would retry the failed carrier")
		}
	}
	if d.RetryError(now.Add(time.Second)) != nil {
		t.Fatal("recovery permanently blocked")
	}
	d.Record(nil, now)
	if d.RetryError(now) != nil {
		t.Fatal("success did not clear failure")
	}
}
