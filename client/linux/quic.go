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
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (q *quicNetStream) LocalAddr() net.Addr {
	return wire.StreamAddr(q.localAddr)
}

func (q *quicNetStream) RemoteAddr() net.Addr {
	return wire.StreamAddr(q.remoteAddr)
}

var (
	quicClientConn      quicpeer.ClientConn
	quicClientTransport io.Closer
	quicClientPacket    net.PacketConn
	quicClientMu        sync.Mutex
	quicDialInProgress  bool
	quicDialWaitChan    chan struct{}
	quicDialLastErr     error
)

func getOrDialQUICClient(cfg *Config) (quicpeer.ClientConn, error) {
	if err := settings.Profile(cfg.ServerAddr, cfg.SNI, cfg.PBK, cfg.User); err != nil {
		return nil, err
	}
	quicClientMu.Lock()
	if quicClientConn != nil {
		select {
		case <-quicClientConn.Context().Done():
			if quicClientTransport != nil {
				_ = quicClientTransport.Close()
				quicClientTransport = nil
			}
			if quicClientPacket != nil {
				_ = quicClientPacket.Close()
				quicClientPacket = nil
			}
			quicClientConn = nil
		default:
			c := quicClientConn
			quicClientMu.Unlock()
			return c, nil
		}
	}

	if quicDialInProgress {
		waitCh := quicDialWaitChan
		quicClientMu.Unlock()
		<-waitCh
		quicClientMu.Lock()
		if quicClientConn != nil {
			c := quicClientConn
			quicClientMu.Unlock()
			return c, nil
		}
		err := quicDialLastErr
		quicClientMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("quic dial completed without connection")
	}

	quicDialInProgress = true
	quicDialWaitChan = make(chan struct{})
	quicClientMu.Unlock()

	defer func() {
		quicClientMu.Lock()
		quicDialInProgress = false
		close(quicDialWaitChan)
		quicClientMu.Unlock()
	}()

	serverUDPAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		dialErr := fmt.Errorf("resolve server addr: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}

	packetNetwork, packetBind := "udp4", "0.0.0.0:0"
	if serverUDPAddr.IP.To4() == nil {
		packetNetwork, packetBind = "udp6", "[::]:0"
	}
	pc, err := net.ListenPacket(packetNetwork, packetBind)
	if err != nil {
		dialErr := fmt.Errorf("listen packet: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
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

	// Synchronize SNI for QUIC with server (if empty or microsoft.com, use speed.cloudflare.com)
	quicSNI := cfg.SNI
	if quicSNI == "" || strings.Contains(strings.ToLower(quicSNI), "microsoft.com") {
		quicSNI = "speed.cloudflare.com"
	}

	tlsConfig := &tls.Config{
		ServerName:         quicSNI,
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

	dialTimeout := 5 * time.Second
	if cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		dialTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	var direct []quicpeer.DirectCredentials
	if cfg.WireVersion == 7 {
		serverKey, err := hex.DecodeString(strings.TrimSpace(cfg.ServerPubKey))
		if err != nil || len(serverKey) != 32 {
			_ = pc.Close()
			return nil, fmt.Errorf("invalid pinned direct QUIC server key")
		}
		direct = []quicpeer.DirectCredentials{{User: cfg.User, Key: userKey, ServerPublicKey: serverKey}}
	}
	conn, closer, err := quicpeer.DialClient(ctx, transport, serverUDPAddr, tlsConfig, quicConfig, cfg.WireVersion, direct...)
	if err != nil {
		_ = closer.Close()
		_ = pc.Close()
		dialErr := fmt.Errorf("quic dial: %w", err)
		quicClientMu.Lock()
		quicDialLastErr = dialErr
		quicClientMu.Unlock()
		return nil, dialErr
	}

	if err := quicpeer.AuthenticateClient(ctx, conn, cfg.User, userKey); err != nil {
		_ = conn.CloseWithError(0x100, "peer authentication failed")
		_ = closer.Close()
		_ = pc.Close()
		quicClientMu.Lock()
		quicDialLastErr = err
		quicClientMu.Unlock()
		return nil, err
	}
	quicClientMu.Lock()
	quicClientConn = conn
	quicClientTransport = closer
	quicClientPacket = pc
	quicDialLastErr = nil
	quicClientMu.Unlock()

	return conn, nil
}

func dialQUICStream(cfg *Config, network, addr string) (net.Conn, error) {
	conn, err := getOrDialQUICClient(cfg)
	if err != nil {
		return nil, err
	}
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
	return &quicNetStream{
		ClientStream: stream,
		localAddr:    conn.LocalAddr(),
		remoteAddr:   conn.RemoteAddr(),
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
