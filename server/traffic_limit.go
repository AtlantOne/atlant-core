package main

import (
	"math"
	"sync/atomic"
)

func totalTraffic(up, down uint64) uint64 {
	if down > math.MaxUint64-up {
		return math.MaxUint64
	}
	return up + down
}

func trafficLimitReached(up, down, limit uint64) bool {
	return limit > 0 && (up >= limit || down >= limit-up)
}

func addTrafficCounter(counter *uint64, amount uint64) {
	for {
		previous := atomic.LoadUint64(counter)
		if atomic.CompareAndSwapUint64(counter, previous, totalTraffic(previous, amount)) {
			return
		}
	}
}
