package tls

import (
	"bytes"
	"crypto/ecdh"
	"errors"
)

// SetClientHelloHook permits changing only Random before transcript hashing.
// The callback runs during Start; callers must not retain the private key.
func (q *UQUICConn) SetClientHelloHook(hook func([]byte, *ecdh.PrivateKey) error) error {
	if q.conn.quic.started || hook == nil {
		return errors.New("invalid QUIC ClientHello hook")
	}
	q.conn.quicClientHelloHook = func(c *UConn) error {
		if c.HandshakeState.State13.KeyShareKeys == nil || c.HandshakeState.State13.KeyShareKeys.Ecdhe == nil {
			return errors.New("QUIC ClientHello hook requires X25519 keyshare")
		}
		original := bytes.Clone(c.HandshakeState.Hello.Raw)
		if len(original) < 39 || original[0] != 1 || original[38] != 0 {
			return errors.New("invalid QUIC ClientHello")
		}
		modified := bytes.Clone(original)
		if err := hook(modified, c.HandshakeState.State13.KeyShareKeys.Ecdhe); err != nil {
			return err
		}
		if len(modified) != len(original) || !bytes.Equal(original[:6], modified[:6]) || !bytes.Equal(original[38:], modified[38:]) {
			return errors.New("QUIC hook may change only ClientHello.random")
		}
		if err := c.SetClientRandom(modified[6:38]); err != nil {
			return err
		}
		if err := c.MarshalClientHello(); err != nil {
			return err
		}
		if !bytes.Equal(c.HandshakeState.Hello.Raw, modified) {
			return errors.New("QUIC ClientHello changed during hook serialization")
		}
		return nil
	}
	return nil
}
