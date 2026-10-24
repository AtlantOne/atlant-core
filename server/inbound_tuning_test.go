package main

import (
	"github.com/hashicorp/yamux"
	"testing"
	"time"
)

func TestInboundQUICConfigUsesListenerTuning(t *testing.T) {
	c := &Config{Quic: QuicConfig{MaxIdleTimeoutSec: 90, KeepAlivePeriodSec: 7, StreamReceiveWindowMB: 12, ConnReceiveWindowMB: 48}}
	q := inboundQUICConfig(c)
	if q.MaxIdleTimeout != 90*time.Second || q.KeepAlivePeriod != 7*time.Second || !q.EnableDatagrams ||
		q.InitialStreamReceiveWindow != 3<<20 || q.MaxStreamReceiveWindow != 12<<20 ||
		q.InitialConnectionReceiveWindow != 12<<20 || q.MaxConnectionReceiveWindow != 48<<20 {
		t.Fatal("listener tuning not applied", q)
	}
	c.Quic.StreamReceiveWindowMB = 24
	if q.MaxStreamReceiveWindow != 12<<20 || inboundQUICConfig(c).MaxStreamReceiveWindow != 24<<20 {
		t.Fatal("runtime settings were shared")
	}
	defaults := inboundQUICConfig(&Config{})
	if defaults.InitialStreamReceiveWindow != 8<<20 || defaults.MaxStreamReceiveWindow != 32<<20 ||
		defaults.InitialConnectionReceiveWindow != 16<<20 || defaults.MaxConnectionReceiveWindow != 64<<20 {
		t.Fatal("default runtime window regressed")
	}
}

func TestInboundYamuxConfigUsesListenerTuning(t *testing.T) {
	c := &Config{Yamux: YamuxConfig{MaxStreamWindowKB: 4096, KeepAlivePeriodSec: 8, WriteTimeoutSec: 17}}
	y := inboundYamuxConfig(c)
	if y.MaxStreamWindowSize != 4<<20 || y.KeepAliveInterval != 8*time.Second || y.ConnectionWriteTimeout != 17*time.Second || !y.EnableKeepAlive {
		t.Fatal("Yamux tuning not applied")
	}
	if err := yamux.VerifyConfig(y); err != nil {
		t.Fatal(err)
	}
}
