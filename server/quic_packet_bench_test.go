package main

import (
	"bytes"
	"testing"
	"time"
)

func BenchmarkQUICPacketCIDLookup(b *testing.B) {
	packet := append([]byte{0x40}, bytes.Repeat([]byte{9}, 1200)...)
	now := time.Now()
	ids := NewShardedAuthMap()
	ids.Set(extractDCID(packet), now)
	for _, variant := range []struct {
		name   string
		lookup func() bool
	}{
		{"copied_key", func() bool { return ids.RefreshExisting(extractDCID(packet), now, 5*time.Minute) }},
		{"packet_key", func() bool { return ids.refreshPacketCID(extractDCIDBytes(packet), now, 5*time.Minute) }},
	} {
		b.Run(variant.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if !variant.lookup() {
						b.Error("known CID rejected")
						return
					}
				}
			})
		})
	}
}
