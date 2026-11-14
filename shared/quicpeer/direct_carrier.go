package quicpeer

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"

	quic "github.com/quic-go/quic-go"
)

type DirectProfile struct {
	Endpoint, ServerName, User, Fingerprint string
	Key, ServerPublicKey                    []byte
}

func (p DirectProfile) PoolKey() [32]byte {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(p.Endpoint), []byte(p.ServerName), []byte(p.User), []byte(p.Fingerprint), p.Key, p.ServerPublicKey} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write(part)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

type carrierResources struct {
	transport io.Closer
	packet    net.PacketConn
}

func (r *carrierResources) Close() error {
	if r.transport != nil {
		_ = r.transport.Close()
	}
	return r.packet.Close()
}

// DialDirectCarrier uses the same direct REALITY proof and exporter-bound
// mutual authentication as the primary wire7 carrier; no HTTPS/bootstrap path.
func DialDirectCarrier(ctx context.Context, p DirectProfile, open func(context.Context, *net.UDPAddr) (net.PacketConn, error)) (*Carrier, error) {
	if len(p.Key) != 32 || len(p.ServerPublicKey) != 32 {
		return nil, errors.New("invalid direct QUIC credentials")
	}
	address, err := ResolveUDP(ctx, p.Endpoint)
	if err != nil {
		return nil, err
	}
	packet, err := open(ctx, address)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: NativeClientSocket(packet)}
	config := ClientConfig()
	config.KeepAlivePeriod = 0 // Unused bulk carriers must be allowed to expire.
	tlsConfig := &tls.Config{ServerName: p.ServerName, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}
	ConfigureTLSPrivacy(tlsConfig, 7)
	conn, closer, err := DialClientWithProfile(ctx, transport, address, tlsConfig, config, 7, p.Fingerprint, DirectCredentials{User: p.User, Key: p.Key, ServerPublicKey: p.ServerPublicKey})
	resources := &carrierResources{transport: closer, packet: packet}
	if err != nil {
		_ = resources.Close()
		return nil, err
	}
	carrier := &Carrier{Conn: conn, Resources: resources}
	if err = AuthenticateClient(ctx, conn, p.User, p.Key); err != nil {
		_ = carrier.Close()
		return nil, err
	}
	return carrier, nil
}

func OpenDirectPacket(_ context.Context, address *net.UDPAddr) (net.PacketConn, error) {
	network, bind := "udp4", "0.0.0.0:0"
	if address.IP.To4() == nil {
		network, bind = "udp6", "[::]:0"
	}
	packet, err := net.ListenPacket(network, bind)
	if err == nil {
		if udp, ok := packet.(*net.UDPConn); ok {
			_ = udp.SetReadBuffer(2 << 20)
			_ = udp.SetWriteBuffer(2 << 20)
		}
	}
	return packet, err
}
