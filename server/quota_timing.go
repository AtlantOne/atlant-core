package main

import (
	"log"
	"sort"
	"sync"
	"time"
)

var quotaTimings struct {
	sync.Mutex
	started       time.Time
	samples       []time.Duration
	calls, failed int
}

// Bounded, credential-free timing samples; no work on the packet hot path.
func recordQuotaTiming(elapsed time.Duration, failed bool) {
	quotaTimings.Lock()
	defer quotaTimings.Unlock()
	now := time.Now()
	if quotaTimings.started.IsZero() {
		quotaTimings.started = now
	}
	quotaTimings.calls++
	if failed {
		quotaTimings.failed++
	}
	if len(quotaTimings.samples) < 256 {
		quotaTimings.samples = append(quotaTimings.samples, elapsed)
	} else {
		quotaTimings.samples[(quotaTimings.calls-1)%256] = elapsed
	}
	if now.Sub(quotaTimings.started) < 30*time.Second {
		return
	}
	samples := append([]time.Duration(nil), quotaTimings.samples...)
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	log.Printf("[QUOTA-TIMING] calls=%d failed=%d samples=%d p50=%s p95=%s max_sample=%s", quotaTimings.calls, quotaTimings.failed, len(samples), samples[(len(samples)-1)/2].Round(time.Microsecond), samples[(len(samples)-1)*95/100].Round(time.Microsecond), samples[len(samples)-1].Round(time.Microsecond))
	quotaTimings.started = now
	quotaTimings.calls, quotaTimings.failed = 0, 0
	quotaTimings.samples = quotaTimings.samples[:0]
}
