package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

var activeInboundSet atomic.Pointer[inboundSet]

// Once the catalog is initialized, its stored identities are authoritative.
// Do not generate a new legacy key file merely because that old file vanished.
func initServerIdentityForCatalog(config *Config) error {
	usersMu.Lock()
	store, err := usersStoreLocked(config.UsersFile)
	if err != nil {
		usersMu.Unlock()
		return err
	}
	catalog, err := store.readInboundCatalog(context.Background())
	usersMu.Unlock()
	if err != nil {
		return err
	}
	if !catalog.Initialized {
		return initServerStaticKey(config.ServerKeyFile)
	}
	if config.WireVersion != 7 || config.LegacyWire {
		return errors.New("stored inbound identities require wire7 without legacy fallback")
	}
	serverStaticECDH, serverStaticPubHexStr = nil, ""
	for _, record := range catalog.Inbounds {
		if serverStaticECDH == nil || record.Settings.ID == "default" {
			serverStaticECDH = record.identity
			serverStaticPubHexStr = hex.EncodeToString(record.identity.PublicKey().Bytes())
		}
		if record.Settings.ID == "default" {
			break
		}
	}
	return nil
}

type inboundBinding struct {
	record inboundRecord
	tcp    net.Listener
	udp    net.PacketConn
}

type inboundSet struct {
	ctx       context.Context
	cancel    context.CancelFunc
	revision  int64
	bindings  []inboundBinding
	workers   sync.WaitGroup
	errors    chan error
	closeOnce sync.Once
	stopClose func() bool
}

func prepareNativeInboundCatalog(ctx context.Context, config *Config) (*inboundCatalog, error) {
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(config.UsersFile)
	if err != nil {
		return nil, err
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil {
		return nil, err
	}
	if !catalog.Initialized && config.WireVersion != 7 {
		return nil, nil
	}
	if config.WireVersion != 7 || config.LegacyWire {
		return nil, errors.New("initialized inbound catalog requires wire7 without legacy fallback")
	}
	if !catalog.Initialized {
		spec, err := legacyInboundSpec(config)
		if err != nil {
			return nil, err
		}
		if _, err := store.initializeInboundCatalog(ctx, &spec, serverStaticECDH); err != nil {
			return nil, err
		}
		catalog, err = store.readInboundCatalog(ctx)
		if err != nil {
			return nil, err
		}
	}
	return &catalog, nil
}

func (s *inboundSet) closeSockets() {
	s.closeOnce.Do(func() {
		for _, binding := range s.bindings {
			for _, socket := range []io.Closer{binding.tcp, binding.udp} {
				if socket != nil {
					_ = socket.Close()
				}
			}
		}
	})
}

func (s *inboundSet) Close() {
	s.cancel()
	s.closeTCPSockets()
	s.workers.Wait()
	s.closeSockets()
	if s.stopClose != nil {
		s.stopClose()
	}
}

// UDP workers terminate QUIC sessions while their sockets can still transmit
// CONNECTION_CLOSE. Closing raw UDP first leaves clients waiting for idle loss.
func (s *inboundSet) closeTCPSockets() {
	for _, binding := range s.bindings {
		if binding.tcp != nil {
			_ = binding.tcp.Close()
		}
	}
}

func (s *inboundSet) report(id, network string, err error) {
	if s.ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("listener unexpectedly stopped")
	}
	select {
	case s.errors <- fmt.Errorf("inbound %s %s: %w", id, network, err):
	default:
	}
	s.cancel()
}

func (s *inboundSet) Wait() error {
	select {
	case err := <-s.errors:
		return err
	case <-s.ctx.Done():
		select {
		case err := <-s.errors:
			return err
		default:
			return s.ctx.Err()
		}
	}
}

// Bind the entire set before starting any handler. A failed bind/start closes
// every socket owned by this candidate, never a socket from another process.
func startInboundSet(parent context.Context, catalog inboundCatalog) (*inboundSet, error) {
	if !catalog.Initialized || catalog.Revision < 1 {
		return nil, errors.New("inbound catalog is not initialized")
	}
	var specs []InboundSpec
	for _, record := range catalog.Inbounds {
		if record.identity == nil {
			return nil, errors.New("inbound has no stored identity")
		}
		specs = append(specs, record.Settings)
	}
	if err := validateInboundSet(specs); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &inboundSet{ctx: ctx, cancel: cancel, revision: catalog.Revision, errors: make(chan error, 1)}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	for _, record := range catalog.Inbounds {
		if !record.Settings.Enabled {
			continue
		}
		binding := inboundBinding{record: record}
		networks := inboundNetworks(record.Settings)
		// Append first so cleanup owns a successful TCP bind even if UDP fails.
		s.bindings = append(s.bindings, binding)
		bound := &s.bindings[len(s.bindings)-1]
		var err error
		if networks["tcp"] {
			bound.tcp, err = (&net.ListenConfig{}).Listen(ctx, "tcp", record.Settings.Listen)
			if err != nil {
				return nil, fmt.Errorf("bind inbound %s TCP: %w", record.Settings.ID, err)
			}
		}
		if networks["udp"] {
			bound.udp, err = (&net.ListenConfig{}).ListenPacket(ctx, "udp", record.Settings.Listen)
			if err != nil {
				return nil, fmt.Errorf("bind inbound %s UDP: %w", record.Settings.ID, err)
			}
		}
	}
	s.stopClose = context.AfterFunc(ctx, s.closeTCPSockets)
	ready := make(chan struct{}, len(s.bindings)*2)
	expected := 0
	for _, binding := range s.bindings {
		if binding.tcp != nil {
			runtime, err := newTCPListenerRuntime(binding.record.Settings, binding.record.identity)
			if err != nil {
				return nil, err
			}
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				s.report(binding.record.Settings.ID, "TCP", serveTCPVPNServer(ctx, binding.tcp, runtime))
			}()
		}
		if binding.udp != nil {
			settings, err := binding.record.Settings.listenerConfig()
			if err != nil {
				return nil, err
			}
			expected++
			s.workers.Add(1)
			go func() {
				defer s.workers.Done()
				s.report(binding.record.Settings.ID, "UDP", serveUDPVPNServerReady(ctx, binding.udp, settings, binding.record.identity, func() { ready <- struct{}{} }))
			}()
		}
	}
	for range expected {
		select {
		case <-ready:
		case <-ctx.Done():
			return nil, s.Wait()
		}
	}
	if ctx.Err() != nil {
		return nil, s.Wait()
	}
	ok = true
	return s, nil
}
