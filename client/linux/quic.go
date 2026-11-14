package main

import (
	"atlant.local/protocol/quicadmission"
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/settings"
	"atlant.local/protocol/wire"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type quicNetStream struct {
	quicpeer.ClientStream
	localAddr   net.Addr
	remoteAddr  net.Addr
	release     func()
	releaseOnce sync.Once
}

func (q *quicNetStream) LocalAddr() net.Addr {
	return wire.StreamAddr(q.localAddr)
}

func (q *quicNetStream) RemoteAddr() net.Addr {
	return wire.StreamAddr(q.remoteAddr)
}

func (q *quicNetStream) Close() error {
	if q.release != nil {
		defer q.releaseOnce.Do(q.release)
	}
	q.ClientStream.CancelRead(0)
	q.ClientStream.CancelWrite(0)
	return nil
}

func (q *quicNetStream) CloseWrite() error { return q.ClientStream.Close() }

const maxQUICCarriers = 4

type quicCarrier struct {
	conn      quicpeer.ClientConn
	transport io.Closer
	packet    net.PacketConn
	mu        sync.Mutex
	dialing   bool
	wait      chan struct{}
	lastErr   error
	cooldown  wire.DialCooldown
	active    int
}

var (
	quicCarriers   [maxQUICCarriers]quicCarrier
	quicCarriersMu sync.Mutex
)

func acquireQUICCarrier(cfg *Config, network string) (*quicCarrier, func()) {
	limit := 1
	if network == "tcp" && cfg.WireVersion == 7 && cfg.QUICParallelConnections > 1 {
		limit = min(cfg.QUICParallelConnections, maxQUICCarriers)
	}
	quicCarriersMu.Lock()
	selected := &quicCarriers[0]
	for i := 1; i < limit; i++ {
		if quicCarriers[i].active < selected.active {
			selected = &quicCarriers[i]
		}
	}
	selected.active++
	quicCarriersMu.Unlock()
	return selected, func() {
		quicCarriersMu.Lock()
		selected.active--
		quicCarriersMu.Unlock()
	}
}

func getOrDialQUICClient(cfg *Config) (quicpeer.ClientConn, error) {
	return quicCarriers[0].getOrDial(cfg)
}

func (carrier *quicCarrier) getOrDial(cfg *Config) (_ quicpeer.ClientConn, resultErr error) {
	if err := settings.Profile(cfg.ServerAddr, cfg.SNI, cfg.PBK, cfg.User); err != nil {
		return nil, err
	}
	carrier.mu.Lock()
	if carrier.conn != nil {
		select {
		case <-carrier.conn.Context().Done():
			if carrier.transport != nil {
				_ = carrier.transport.Close()
				carrier.transport = nil
			}
			if carrier.packet != nil {
				_ = carrier.packet.Close()
				carrier.packet = nil
			}
			carrier.conn = nil
		default:
			c := carrier.conn
			carrier.mu.Unlock()
			return c, nil
		}
	}

	if carrier.dialing {
		waitCh := carrier.wait
		carrier.mu.Unlock()
		<-waitCh
		carrier.mu.Lock()
		if carrier.conn != nil {
			c := carrier.conn
			carrier.mu.Unlock()
			return c, nil
		}
		err := carrier.lastErr
		carrier.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("quic dial completed without connection")
	}

	if err := carrier.cooldown.RetryError(time.Now()); err != nil {
		carrier.mu.Unlock()
		return nil, err
	}
	carrier.dialing = true
	carrier.wait = make(chan struct{})
	carrier.mu.Unlock()

	defer func() {
		carrier.mu.Lock()
		carrier.lastErr = resultErr
		carrier.cooldown.Record(resultErr, time.Now())
		carrier.dialing = false
		close(carrier.wait)
		carrier.mu.Unlock()
	}()

	dialTimeout := 5 * time.Second
	if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		dialTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	serverUDPAddr, err := quicpeer.ResolveUDP(ctx, cfg.ServerAddr)
	if err != nil {
		dialErr := fmt.Errorf("resolve server addr: %w", err)
		carrier.mu.Lock()
		carrier.lastErr = dialErr
		carrier.mu.Unlock()
		return nil, dialErr
	}

	packetNetwork, packetBind := "udp4", "0.0.0.0:0"
	if serverUDPAddr.IP.To4() == nil {
		packetNetwork, packetBind = "udp6", "[::]:0"
	}
	pc, err := net.ListenPacket(packetNetwork, packetBind)
	if err != nil {
		dialErr := fmt.Errorf("listen packet: %w", err)
		carrier.mu.Lock()
		carrier.lastErr = dialErr
		carrier.mu.Unlock()
		return nil, dialErr
	}
	if uConn, ok := pc.(*net.UDPConn); ok {
		_ = uConn.SetReadBuffer(8 * 1024 * 1024)
		_ = uConn.SetWriteBuffer(8 * 1024 * 1024)
	}

	userKey := parsePBKBytes(cfg.PBK)
	var generator quic.ConnectionIDGenerator = NewRealityConnIDGenerator(cfg.User, userKey)
	if cfg.WireVersion == 3 || cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		bootstrap, err := dialQUICBootstrap(cfg)
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("REALITY CID bootstrap: %w", err)
		}
		var pool *quicadmission.CIDPool
		if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
			var bound *quicadmission.BoundPacketConn
			pool, bound, err = quicadmission.FetchBoundPoolVersion(context.Background(), bootstrap, pc, byte(cfg.WireVersion))
			if err == nil {
				pc = bound
				defer bound.CloseBootstrap()
			}
		} else {
			pool, err = quicadmission.FetchPool(context.Background(), bootstrap)
		}
		if err != nil {
			pc.Close()
			return nil, err
		}
		generator = pool
		if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
			generator = &quicadmission.ZeroCIDGenerator{}
		}
	}
	transport := &quic.Transport{
		// Preserve native UDP OOB / batching capabilities. Any admission wrapper
		// already present in pc must remain in place for older wire formats.
		Conn:                  quicpeer.NativeClientSocket(pc),
		ConnectionIDGenerator: generator,
	}

	tlsConfig := &tls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no peer cert")
			}
			return nil
		},
		NextProtos: []string{"h3"},
	}
	quicpeer.ConfigureTLSPrivacy(tlsConfig, cfg.WireVersion)

	quicConfig := quicpeer.ClientConfig()
	if carrier != &quicCarriers[0] {
		quicConfig.KeepAlivePeriod = 0
	}

	var direct []quicpeer.DirectCredentials
	if cfg.WireVersion == 7 {
		serverKey, err := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
		if err != nil || len(serverKey) != 32 {
			_ = pc.Close()
			return nil, fmt.Errorf("invalid pinned direct QUIC server key")
		}
		direct = []quicpeer.DirectCredentials{{User: cfg.User, Key: userKey, ServerPublicKey: serverKey}}
	}
	conn, closer, err := quicpeer.DialClientWithProfile(ctx, transport, serverUDPAddr, tlsConfig, quicConfig, cfg.WireVersion, cfg.QUICFingerprint, direct...)
	if err != nil {
		_ = closer.Close()
		_ = pc.Close()
		dialErr := fmt.Errorf("quic dial: %w", err)
		carrier.mu.Lock()
		carrier.lastErr = dialErr
		carrier.mu.Unlock()
		return nil, dialErr
	}

	if err := quicpeer.AuthenticateClient(ctx, conn, cfg.User, userKey); err != nil {
		_ = conn.CloseWithError(0x100, "peer authentication failed")
		_ = closer.Close()
		_ = pc.Close()
		carrier.mu.Lock()
		carrier.lastErr = err
		carrier.mu.Unlock()
		return nil, err
	}
	carrier.mu.Lock()
	carrier.conn = conn
	carrier.transport = closer
	carrier.packet = pc
	carrier.lastErr = nil
	carrier.mu.Unlock()
	if carrier != &quicCarriers[0] {
		context.AfterFunc(conn.Context(), func() {
			carrier.mu.Lock()
			defer carrier.mu.Unlock()
			if carrier.conn == conn {
				carrier.conn, carrier.transport, carrier.packet = nil, nil, nil
				_ = closer.Close()
				_ = pc.Close()
			}
		})
	}

	return conn, nil
}

func dialPrimaryQUICStream(cfg *Config, network, addr string) (net.Conn, error) {
	carrier, release := acquireQUICCarrier(cfg, network)
	conn, err := carrier.getOrDial(cfg)
	if err != nil && carrier != &quicCarriers[0] {
		release()
		carrier, release = acquireQUICCarrier(cfg, "")
		conn, err = carrier.getOrDial(cfg)
	}
	if err != nil {
		release()
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			release()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	var protoByte byte = 0x11 // TCP default
	if network == "udp" {
		protoByte = 0x12
	}

	minPadding, maxPadding := 0, 0
	if cfg.PaddingEnabled {
		minPadding, maxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	}
	_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteQUICHeader(stream, wire.QUICHeader{UserTag: getUserTag(cfg.User), Protocol: protoByte, Destination: addr}, minPadding, maxPadding); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	transferred = true
	return &quicNetStream{
		ClientStream: stream,
		localAddr:    conn.LocalAddr(),
		remoteAddr:   conn.RemoteAddr(),
		release:      release,
	}, nil
}

type RealityQUICPacketConn struct {
	net.PacketConn
	secretKey []byte
}

func NewRealityQUICPacketConn(conn net.PacketConn, secretKey []byte) *RealityQUICPacketConn {
	return &RealityQUICPacketConn{
		PacketConn: conn,
		secretKey:  secretKey,
	}
}

func (r *RealityQUICPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return r.PacketConn.WriteTo(p, addr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type RealityConnIDGenerator struct{ generator *quicpeer.CIDGenerator }

func NewRealityConnIDGenerator(user string, key []byte) *RealityConnIDGenerator {
	return &RealityConnIDGenerator{generator: quicpeer.NewCIDGenerator(user, key)}
}

func (g *RealityConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return g.generator.GenerateConnectionID()
}
func (g *RealityConnIDGenerator) ConnectionIDLen() int { return g.generator.ConnectionIDLen() }
