package quicpeer

import (
	"time"

	"github.com/quic-go/quic-go"
)

// ClientConfig returns a fresh config for each tunnel. The public Initial
// audit uses this same configuration as Android, Linux and Windows; otherwise
// a test of quic-go defaults can miss the parameters actually sent by Atlant.
func ClientConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		EnableDatagrams:                true,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		MaxStreamReceiveWindow:         32 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
	}
}
