package quicpeer

import (
	"atlant.local/protocol/auth"
	"atlant.local/protocol/quicreality"
	"context"
	"crypto/ecdh"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	browser "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// Keep the maintained server stack and wire4 transport unchanged. Only the
// explicit wire6 client uses the pinned browser Initial implementation.
type ClientStream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

type ClientConn interface {
	Context() context.Context
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	OpenStreamSync(context.Context) (ClientStream, error)
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
	CloseWithError(quic.ApplicationErrorCode, string) error
	ExportBinding() ([]byte, error)
}

type stockClient struct{ *quic.Conn }

func (c *stockClient) OpenStreamSync(ctx context.Context) (ClientStream, error) {
	return c.Conn.OpenStreamSync(ctx)
}
func (c *stockClient) ExportBinding() ([]byte, error) { return auth.Binding(c.ConnectionState().TLS) }

type browserStream struct{ *browser.Stream }

func (s *browserStream) CancelRead(code quic.StreamErrorCode) {
	s.Stream.CancelRead(browser.StreamErrorCode(code))
}
func (s *browserStream) CancelWrite(code quic.StreamErrorCode) {
	s.Stream.CancelWrite(browser.StreamErrorCode(code))
}

type browserClient struct{ *browser.Conn }

func (c *browserClient) OpenStreamSync(ctx context.Context) (ClientStream, error) {
	s, err := c.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &browserStream{s}, nil
}
func (c *browserClient) CloseWithError(code quic.ApplicationErrorCode, reason string) error {
	return c.Conn.CloseWithError(browser.ApplicationErrorCode(code), reason)
}
func (c *browserClient) ExportBinding() ([]byte, error) {
	state := c.ConnectionState().TLS
	if state.Version != utls.VersionTLS13 || !state.HandshakeComplete {
		return nil, auth.ErrAuthentication
	}
	return state.ExportKeyingMaterial(auth.ExporterLabel, nil, 32)
}
func (c *browserClient) SendDatagram(packet []byte) error {
	err := c.Conn.SendDatagram(packet)
	var tooLarge *browser.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: tooLarge.MaxDatagramPayloadSize}
	}
	return err
}

type browserZeroCID struct{}

func (browserZeroCID) ConnectionIDLen() int { return 0 }
func (browserZeroCID) GenerateConnectionID() (browser.ConnectionID, error) {
	return browser.ConnectionIDFromBytes(nil), nil
}

type DirectCredentials struct {
	User            string
	Key             []byte
	ServerPublicKey []byte
}

func DialClient(ctx context.Context, transport *quic.Transport, addr net.Addr, tlsConfig *tls.Config, config *quic.Config, version int, direct ...DirectCredentials) (ClientConn, io.Closer, error) {
	if version != 6 && version != 7 {
		transport.Conn = legacyClientSocket(transport.Conn)
		conn, err := transport.Dial(ctx, addr, tlsConfig, config)
		if err != nil {
			return nil, transport, err
		}
		return &stockClient{conn}, transport, nil
	}
	// The two TLS stacks expose different ConnectionState types. Never silently
	// discard a caller's additional certificate-verification policy.
	if tlsConfig.VerifyConnection != nil {
		return nil, transport, errors.New("wire6: VerifyConnection is unsupported; use VerifyPeerCertificate")
	}
	profile := browser.QUICChrome_146_IPv4
	if udp, ok := addr.(*net.UDPAddr); ok && udp.IP.To4() == nil && udp.IP.To16() != nil {
		profile = browser.QUICChrome_146_IPv6
	}
	spec, err := browser.QUICID2Spec(profile)
	if err != nil {
		return nil, transport, err
	}
	if err := configureChromeFlight(&spec, profile == browser.QUICChrome_146_IPv6); err != nil {
		return nil, transport, err
	}
	var admission quicreality.Admission
	var bound bool
	if version == 7 {
		if len(direct) != 1 || len(direct[0].Key) != 32 || len(direct[0].ServerPublicKey) != 32 {
			return nil, transport, quicreality.ErrAuthentication
		}
		creds := direct[0]
		spec.ClientHelloHook = func(hello []byte, key *ecdh.PrivateKey) error {
			var err error
			admission, err = quicreality.BindHello(hello, creds.User, creds.Key, key, creds.ServerPublicKey, time.Now())
			bound = err == nil
			return err
		}
	}
	bt := &browser.Transport{Conn: transport.Conn, ConnectionIDGenerator: browserZeroCID{}}
	bc := &browser.Config{EnableDatagrams: true, MaxIdleTimeout: config.MaxIdleTimeout, KeepAlivePeriod: config.KeepAlivePeriod,
		InitialStreamReceiveWindow: config.InitialStreamReceiveWindow, MaxStreamReceiveWindow: config.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.InitialConnectionReceiveWindow, MaxConnectionReceiveWindow: config.MaxConnectionReceiveWindow}
	for _, version := range config.Versions {
		bc.Versions = append(bc.Versions, browser.Version(version))
	}
	// Verification policy is preserved, not replaced by mimicry. Application
	// access still requires the same TLS-exporter-bound mutual PSK proof.
	tc := &utls.Config{ServerName: tlsConfig.ServerName, NextProtos: []string{"h3"}, MinVersion: utls.VersionTLS13,
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify, RootCAs: tlsConfig.RootCAs,
		VerifyPeerCertificate: tlsConfig.VerifyPeerCertificate, SessionTicketsDisabled: true}
	if version == 7 {
		tc.InsecureSkipVerify = true // replaced by pinned-static-DH/PSK identity proof, not hostname-only trust
		tc.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			if !bound {
				return quicreality.ErrAuthentication
			}
			if err := quicreality.VerifyCertificate(raw, tlsConfig.ServerName, admission); err != nil {
				return err
			}
			if tlsConfig.VerifyPeerCertificate != nil {
				return tlsConfig.VerifyPeerCertificate(raw, chains)
			}
			return nil
		}
	}
	conn, err := (&browser.UTransport{Transport: bt, QUICSpec: &spec}).Dial(ctx, addr, tc, bc)
	if err != nil {
		return nil, bt, err
	}
	return &browserClient{conn}, bt, nil
}

func AuthenticateClient(ctx context.Context, conn ClientConn, user string, key []byte) error {
	binding, err := conn.ExportBinding()
	if err != nil {
		return err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer prepare(ctx, stream)()
	return auth.Client(stream, user, key, binding)
}
