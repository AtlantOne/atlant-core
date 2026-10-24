package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func runExchange(t *testing.T, clientKey, serverKey, clientBinding, serverBinding []byte, known bool) (error, error) {
	t.Helper()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(time.Second))
	_ = right.SetDeadline(time.Now().Add(time.Second))
	serverDone := make(chan error, 1)
	go func() {
		defer right.Close()
		_, err := Server(right, serverBinding, func(user string) ([]byte, bool) { return serverKey, known && user == "alice" })
		serverDone <- err
	}()
	err := Client(left, "alice", clientKey, clientBinding)
	_ = left.Close()
	return err, <-serverDone
}

func TestMutualProof(t *testing.T) {
	key, binding := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	clientErr, serverErr := runExchange(t, key, key, binding, binding, true)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("client=%v server=%v", clientErr, serverErr)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	binding := bytes.Repeat([]byte{9}, 32)
	clientErr, serverErr := runExchange(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), binding, binding, true)
	if clientErr == nil || !errors.Is(serverErr, ErrAuthentication) {
		t.Fatal("wrong secret accepted")
	}
}

func TestTerminatingRelayBindingRejected(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	clientErr, serverErr := runExchange(t, key, key, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), true)
	if clientErr == nil || !errors.Is(serverErr, ErrAuthentication) {
		t.Fatal("proof from another TLS session accepted")
	}
}

func TestUnknownOrDisabledUserRejected(t *testing.T) {
	key, binding := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	clientErr, serverErr := runExchange(t, key, key, binding, binding, false)
	if clientErr == nil || !errors.Is(serverErr, ErrAuthentication) {
		t.Fatal("unknown user accepted")
	}
}

type scriptedStream struct {
	io.Reader
	io.Writer
}

func TestClientProofCannotBeReflectedAsServerProof(t *testing.T) {
	key, binding := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	stream := scriptedStream{bytes.NewReader(proof("client", "alice", key, binding)), io.Discard}
	if !errors.Is(Client(stream, "alice", key, binding), ErrAuthentication) {
		t.Fatal("reflected client proof accepted")
	}
}

func TestMalformedLengthsAndLegacyPeersRejected(t *testing.T) {
	for _, length := range []uint16{0, 65, 65535} {
		header := append([]byte{}, magic[:]...)
		header = binary.BigEndian.AppendUint16(header, length)
		_, err := Server(scriptedStream{bytes.NewReader(header), io.Discard}, make([]byte, 32), func(string) ([]byte, bool) { t.Fatal("invalid header reached key lookup"); return nil, false })
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("length %d: %v", length, err)
		}
	}
	_, err := Server(scriptedStream{bytes.NewReader(make([]byte, 10)), io.Discard}, make([]byte, 32), func(string) ([]byte, bool) { return nil, false })
	if !errors.Is(err, ErrAuthentication) {
		t.Fatal("legacy peer accepted")
	}
}

func TestUnfinishedTLSCannotSupplyBinding(t *testing.T) {
	if _, err := Binding(tls.ConnectionState{}); !errors.Is(err, ErrAuthentication) {
		t.Fatal("unfinished TLS accepted")
	}
}
