package main

import (
	"fmt"
	"sync/atomic"
	"testing"
)

func BenchmarkTrafficAccountingParallel(b *testing.B) {
	usersMu.Lock()
	previousDB := usersDB
	previousAccess := subscriptionAccess.Swap(nil)
	previousDirty := usersDirty.Load()
	usersDB = &userDB{Version: 1, Users: map[string]*userRecord{}}
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("bench%d", i)
		usersDB.Users[name] = &userRecord{Name: name, Enabled: true}
	}
	usersMu.Unlock()
	b.Cleanup(func() {
		usersMu.Lock()
		usersDB = previousDB
		subscriptionAccess.Store(previousAccess)
		usersDirty.Store(previousDirty)
		usersMu.Unlock()
	})
	var next atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		name := fmt.Sprintf("bench%d", next.Add(1)%16)
		for pb.Next() {
			if !recordUserTraffic(name, 32768, 0) {
				b.Fatal("benchmark account denied")
			}
		}
	})
}
