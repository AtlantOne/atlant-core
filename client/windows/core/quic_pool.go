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

func paceClientConn(c net.Conn, cfg *Config, udp, reverse bool) net.Conn {
	return clientBandwidth.Wrap(cfg.ServerAddr+"\x00"+cfg.User, cfg.UpMbps, cfg.DownMbps, c, udp, reverse)
}

func dialQUICStream(cfg *Config, network, addr string) (result net.Conn, err error) {
	defer func() {
		if err == nil && result != nil {
			result = paceClientConn(result, cfg, network == "udp", false)
		}
	}()
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
	stream, err := quicpeer.OpenBulkStream(context.Background(), &bulkQUICPool, profile, cfg.QUICParallelConnections, openBulkPacket, addr, getUserTag(cfg.User), minPadding, maxPadding)
	if err != nil {
		return nil, err
	}
	return stream, err
}

func openBulkPacket(ctx context.Context, address *net.UDPAddr) (net.PacketConn, error) {
	if physicalLocalIP == nil || (physicalLocalIP.To4() == nil) != (address.IP.To4() == nil) {
		return quicpeer.OpenDirectPacket(ctx, address)
	}
	network := "udp4"
	if address.IP.To4() == nil {
		network = "udp6"
	}
	packet, err := net.ListenPacket(network, net.JoinHostPort(physicalLocalIP.String(), "0"))
	if err != nil {
		return nil, err
	} // Do not silently route a bulk socket into TUN.
	udp := packet.(*net.UDPConn)
	_ = udp.SetReadBuffer(2 << 20)
	_ = udp.SetWriteBuffer(2 << 20)
	return packet, nil
}
