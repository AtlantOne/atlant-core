package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Durable local SQLite commits, not RAM/network throughput. Each operation
// updates one user's counters, matching the common periodic flush workload.
func BenchmarkSQLiteStatsFlush(b *testing.B) {
	for _, count := range []int{4, 1000} {
		b.Run(fmt.Sprintf("users_%d", count), func(b *testing.B) {
			store, err := openSQLiteUsers(filepath.Join(b.TempDir(), "users.db"))
			if err != nil {
				b.Fatal(err)
			}
			defer store.Close()
			snapshot := &userDB{Version: 1, Users: map[string]*userRecord{}}
			for i := 0; i < count; i++ {
				name := fmt.Sprintf("user_%04d", i)
				snapshot.Users[name] = &userRecord{Name: name, PBK: strings.Repeat("ab", 32), Enabled: true}
			}
			if err = store.save(context.Background(), snapshot, ""); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snapshot.Users["user_0000"].UpBytes++
				if err = store.save(context.Background(), snapshot, ""); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
