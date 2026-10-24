package main

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log"
	"net"
	"sync"
)

func legacyInboundSpec(config *Config) (InboundSpec, error) {
	if config == nil {
		return InboundSpec{}, errors.New("server configuration is required")
	}
	configMu.RLock()
	c := *config
	configMu.RUnlock()
	if c.WireVersion != 7 || c.LegacyWire {
		return InboundSpec{}, errors.New("native inbound migration requires wire7 without legacy admission")
	}
	host, port, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		host, port = "", c.ServerAddr
	}
	if port == "" {
		port = "443"
	}
	path := c.Path
	if path == "" {
		path = c.ServerPath
	}
	if path == "" {
		path = "/api/v1/sync"
	}
	spec := InboundSpec{ID: "default", Name: "Default inbound", Enabled: true,
		Listen: net.JoinHostPort(host, port), AdvertiseAddr: c.AdvertiseAddr,
		SNI: c.SNI, Transports: []string{"tcp", "xhttp", "quic"}, WireVersion: 7,
		XHTTPPath: path, UpMbps: c.GetUpMbps(), DownMbps: c.GetDownMbps(), Quic: c.Quic, Yamux: c.Yamux}
	return spec, spec.validate()
}

// Only listener-owned fields are copied. API credentials, quota workers and the
// SQLite writer belong to the process, not to individual listeners.
func (s InboundSpec) listenerConfig() (*Config, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	c := DefaultConfig()
	c.InboundID = s.ID
	c.ServerAddr, c.AdvertiseAddr, c.SNI = s.Listen, s.AdvertiseAddr, s.SNI
	c.WireVersion, c.LegacyWire = s.WireVersion, false
	c.Path, c.ServerPath = s.XHTTPPath, s.XHTTPPath
	c.UpMbps, c.DownMbps = s.UpMbps, s.DownMbps
	c.Quic, c.Yamux = s.Quic, s.Yamux
	return c, nil
}

func newTCPListenerRuntime(spec InboundSpec, identity *ecdh.PrivateKey) (*tcpListenerRuntime, error) {
	settings, err := spec.listenerConfig()
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, errors.New("inbound requires a REALITY identity")
	}
	r := &tcpListenerRuntime{config: settings, identity: identity}
	for _, transport := range spec.Transports {
		r.tcp = r.tcp || transport == "tcp"
		r.xhttp = r.xhttp || transport == "xhttp"
	}
	if !r.tcp && !r.xhttp {
		return nil, errors.New("inbound has no TCP transport")
	}
	return r, nil
}

func serveTCPVPNServer(ctx context.Context, listener net.Listener, runtime *tcpListenerRuntime) error {
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	closeActive := func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range active {
			_ = conn.Close()
		}
	}
	stop := context.AfterFunc(ctx, closeActive)
	defer func() {
		stop()
		closeActive()
		workers.Wait()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		limited, ok := acceptedConnections.take(conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		mu.Lock()
		if ctx.Err() != nil {
			mu.Unlock()
			_ = limited.Close()
			return ctx.Err()
		}
		active[limited] = struct{}{}
		mu.Unlock()
		log.Printf("[ACCEPT] %s -> %s", limited.RemoteAddr(), limited.LocalAddr())
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				_ = limited.Close()
				mu.Lock()
				delete(active, limited)
				mu.Unlock()
			}()
			runtime.handleForkContext(ctx, limited)
		}()
	}
}
