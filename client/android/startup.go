//go:build android || (linux && atlanttest)

package atlant

import (
	"context"
	"net"
)

func authenticateTunnelCarrier(cfg *Config, allowFallback bool, quicProbe func(*Config) error, tcpProbe func(*Config) (net.Conn, error)) error {
	if cfg.Transport == "quic" || cfg.Transport == "udp" {
		if err := quicProbe(cfg); err == nil || !allowFallback {
			return err
		}
	}
	conn, err := tcpProbe(cfg)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

// Startup owns lifecycleMu. A failed attempt must release prewarmed carriers
// too: StopVPN otherwise returns early once isRunning has been cleared.
func resetFailedVPNStart(cancel context.CancelFunc) {
	cancel()
	closeRealitySession()
	closeXHTTPTransport()
	closeQUICClient("VPN startup failed")
	runWg.Wait()
	mu.Lock()
	isRunning = false
	activeConfig = nil
	cancelFunc = nil
	mu.Unlock()
}
