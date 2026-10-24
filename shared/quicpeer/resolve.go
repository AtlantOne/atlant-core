package quicpeer

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// ResolveUDP includes DNS in the handshake budget. net.ResolveUDPAddr uses a
// background lookup and can otherwise outlive cancellation of a VPN session.
func ResolveUDP(ctx context.Context, endpoint string) (*net.UDPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	host, service, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(service)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid QUIC endpoint port")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("QUIC endpoint has no addresses")
	}
	best := addresses[0]
	for _, address := range addresses {
		if address.IP.To4() != nil {
			best = address
			break
		}
	}
	return &net.UDPAddr{IP: best.IP, Zone: best.Zone, Port: port}, nil
}
