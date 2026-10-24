package wire

import "time"

// IdleDeadline avoids resetting the runtime poll timer for every packet. It is
// owned by one I/O direction, not shared between goroutines. The idle timeout
// can become at most one second stricter; it is never extended beyond limit.
type IdleDeadline struct{ next time.Time }

func (d *IdleDeadline) Update(now time.Time, limit time.Duration, set func(time.Time) error) error {
	if now.Before(d.next) {
		return nil
	}
	if err := set(now.Add(limit)); err != nil {
		return err
	}
	interval := min(time.Second, limit/4)
	d.next = now.Add(interval)
	return nil
}
