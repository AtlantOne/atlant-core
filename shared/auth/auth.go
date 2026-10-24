// Package auth provides mutual PSK confirmation bound to a TLS 1.3 session.
// The TLS exporter prevents a terminating relay from reusing another session's
// proof; distinct role labels prevent reflecting the client's proof back to it.
package auth

import (
	"atlant.local/protocol/wire"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
)

const ExporterLabel = "EXPORTER-Atlant-QUIC-Auth-v1"
const bindingSize = 32
const proofSize = sha256.Size

var magic = [8]byte{'A', 'T', 'L', 'A', 'U', 'T', 'H', 1}
var ErrAuthentication = errors.New("QUIC peer authentication failed; verify the profile key and upgrade both client and server")

// Binding must be derived independently on each endpoint, never sent on wire.
func Binding(state tls.ConnectionState) ([]byte, error) {
	if state.Version != tls.VersionTLS13 || !state.HandshakeComplete {
		return nil, ErrAuthentication
	}
	return state.ExportKeyingMaterial(ExporterLabel, nil, bindingSize)
}

func validUser(user string) bool {
	if len(user) < 1 || len(user) > 64 {
		return false
	}
	for _, b := range []byte(user) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

func proof(role string, user string, key, binding []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("Atlant QUIC auth v1\x00" + role + "\x00"))
	_, _ = mac.Write(binding)
	_, _ = mac.Write([]byte(user))
	return mac.Sum(nil)
}

func Client(stream io.ReadWriter, user string, key, binding []byte) error {
	if !validUser(user) || len(key) != 32 || len(binding) != bindingSize {
		return ErrAuthentication
	}
	request := make([]byte, len(magic)+2+len(user)+proofSize)
	copy(request, magic[:])
	binary.BigEndian.PutUint16(request[8:10], uint16(len(user)))
	copy(request[10:], user)
	copy(request[10+len(user):], proof("client", user, key, binding))
	if err := wire.WriteFull(stream, request); err != nil {
		return err
	}
	var response [proofSize]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil {
		return err
	}
	if !hmac.Equal(response[:], proof("server", user, key, binding)) {
		return ErrAuthentication
	}
	return nil
}

// Lookup returns the enabled user's key. Unknown users receive no proof.
func Server(stream io.ReadWriter, binding []byte, lookup func(string) ([]byte, bool)) (string, error) {
	if len(binding) != bindingSize {
		return "", ErrAuthentication
	}
	var header [10]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return "", err
	}
	if !hmac.Equal(header[:8], magic[:]) {
		return "", ErrAuthentication
	}
	n := int(binary.BigEndian.Uint16(header[8:]))
	if n < 1 || n > 64 {
		return "", ErrAuthentication
	}
	request := make([]byte, n+proofSize)
	if _, err := io.ReadFull(stream, request); err != nil {
		return "", err
	}
	user := string(request[:n])
	if !validUser(user) {
		return "", ErrAuthentication
	}
	key, ok := lookup(user)
	if !ok || len(key) != 32 || !hmac.Equal(request[n:], proof("client", user, key, binding)) {
		return "", ErrAuthentication
	}
	if err := wire.WriteFull(stream, proof("server", user, key, binding)); err != nil {
		return "", err
	}
	return user, nil
}
