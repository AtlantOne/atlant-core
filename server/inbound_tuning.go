package main

import (
	"io"
	"time"

	"github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
)

// A quarter-sized initial window retains growth under backpressure, while the
// configured maximum bounds the auto-tuned receive window for this listener.
func inboundQUICConfig(c *Config) *quic.Config {
	stream, connection := c.GetQuicStreamReceiveWindow(), c.GetQuicConnReceiveWindow()
	return &quic.Config{
		MaxIdleTimeout:                 c.GetQuicMaxIdleTimeout(),
		EnableDatagrams:                true,
		KeepAlivePeriod:                c.GetQuicKeepAlivePeriod(),
		InitialStreamReceiveWindow:     stream / 4,
		MaxStreamReceiveWindow:         stream,
		InitialConnectionReceiveWindow: connection / 4,
		MaxConnectionReceiveWindow:     connection,
	}
}

func inboundYamuxConfig(c *Config) *yamux.Config {
	result := yamux.DefaultConfig()
	result.EnableKeepAlive = true
	result.KeepAliveInterval = time.Duration(c.Yamux.KeepAlivePeriodSec) * time.Second
	if result.KeepAliveInterval == 0 {
		result.KeepAliveInterval = 25 * time.Second
	}
	result.ConnectionWriteTimeout = time.Duration(c.Yamux.WriteTimeoutSec) * time.Second
	if result.ConnectionWriteTimeout == 0 {
		result.ConnectionWriteTimeout = 15 * time.Second
	}
	result.MaxStreamWindowSize = c.GetYamuxStreamWindow()
	result.Logger = nil
	result.LogOutput = io.Discard
	return result
}
