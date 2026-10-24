package wire

import "time"

// DialCooldown shares a failed carrier attempt with callers queued on the
// session mutex. Otherwise each waiter starts another full handshake timeout.
// The caller must hold that mutex. A successful dial clears the failure.
type DialCooldown struct {
	err   error
	until time.Time
}

func (d *DialCooldown) RetryError(now time.Time) error {
	if now.Before(d.until) {
		return d.err
	}
	return nil
}

func (d *DialCooldown) Record(err error, now time.Time) {
	d.err = err
	if err == nil {
		d.until = time.Time{}
		return
	}
	d.until = now.Add(time.Second)
}
