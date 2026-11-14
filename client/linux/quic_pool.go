package main

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/settings"
	"atlant.local/protocol/wire"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

var bulkQUICPool quicpeer.StreamPool
var clientBandwidth wire.BandwidthGroup

func dialQUICStream(cfg *Config, network, addr string) (net.Conn, error) {
	if cfg.WireVersion != 7 || network != "tcp" {
		return dialPrimaryQUICStream(cfg, network, addr)
	}
	if err := settings.Profile(cfg.ServerAddr, cfg.SNI, cfg.PBK, cfg.User); err != nil {
		return nil, err
	}
	serverKey, err := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
	if err != nil || len(serverKey) != 32 {
		return nil, fmt.Errorf("invalid pinned QUIC server key")
	}
	profile := quicpeer.DirectProfile{Endpoint: cfg.ServerAddr, ServerName: cfg.SNI, User: cfg.User, Key: parsePBKBytes(cfg.PBK), ServerPublicKey: serverKey, Fingerprint: cfg.QUICFingerprint}
	minPadding, maxPadding := 0, 0
	if cfg.PaddingEnabled {
		minPadding, maxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	}
	return quicpeer.OpenBulkStream(context.Background(), &bulkQUICPool, profile, cfg.QUICParallelConnections, quicpeer.OpenDirectPacket, addr, getUserTag(cfg.User), minPadding, maxPadding)
}
