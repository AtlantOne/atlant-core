//go:build android || (linux && atlanttest)

package atlant

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/settings"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var bulkQUICPool quicpeer.StreamPool

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
	endpoint := cfg.ServerAddr
	if IsPortHoppingEnabled() {
		host, _, err := net.SplitHostPort(endpoint)
		if err == nil {
			endpoint = net.JoinHostPort(host, strconv.Itoa(20000+int((time.Now().Unix()/120)%30000)))
		}
	}
	profile := quicpeer.DirectProfile{Endpoint: endpoint, ServerName: cfg.SNI, User: cfg.User, Key: parsePBKBytes(cfg.PBK), ServerPublicKey: serverKey, Fingerprint: cfg.QUICFingerprint}
	minPadding, maxPadding := 0, 0
	if cfg.PaddingEnabled {
		minPadding, maxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	}
	return quicpeer.OpenBulkStream(cfg.context(), &bulkQUICPool, profile, 0, openBulkPacket, addr, getUserTag(cfg.User), minPadding, maxPadding)
}

func openBulkPacket(ctx context.Context, address *net.UDPAddr) (net.PacketConn, error) {
	packet, err := quicpeer.OpenDirectPacket(ctx, address)
	if err != nil {
		return nil, err
	}
	udp := packet.(*net.UDPConn)
	raw, err := udp.SyscallConn()
	if err != nil {
		packet.Close()
		return nil, err
	}
	var protectErr error
	if err = raw.Control(func(fd uintptr) { protectErr = protectSocket(int(fd)) }); err != nil {
		packet.Close()
		return nil, err
	}
	if protectErr != nil {
		packet.Close()
		return nil, protectErr
	}
	return packet, nil
}
