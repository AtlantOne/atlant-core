package wire

import (
	"sync"
	"time"
)

// DeadlineWatch cancels an HTTP/2 stream at its deadline. Checking a timestamp
// before Read/Write alone cannot interrupt an operation that is already blocked.
// The caller closes only that request, never a pooled HTTP/2 connection.
type DeadlineWatch struct {
	mu         sync.Mutex
	timer      *time.Timer
	generation uint64
	deadline   time.Time
	cancel     func()
	active     int
}

func (w *DeadlineWatch) Set(deadline time.Time, cancel func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadline = deadline
	w.cancel = cancel
	w.scheduleLocked()
}

func (w *DeadlineWatch) scheduleLocked() {
	w.generation++
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if w.deadline.IsZero() || w.active == 0 {
		return
	}
	generation := w.generation
	cancel := w.cancel
	w.timer = time.AfterFunc(time.Until(w.deadline), func() {
		w.mu.Lock()
		current := w.generation == generation
		w.mu.Unlock()
		if current {
			cancel()
		}
	})
}

func (w *DeadlineWatch) Begin() { w.mu.Lock(); defer w.mu.Unlock(); w.active++; w.scheduleLocked() }
func (w *DeadlineWatch) End() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active > 0 {
		w.active--
	}
	w.scheduleLocked()
}
func (w *DeadlineWatch) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadline = time.Time{}
	w.cancel = nil
	w.active = 0
	w.scheduleLocked()
}
