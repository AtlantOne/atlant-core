package atlant

import (
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"testing"
)

func TestHTTP3PrefersExistingQUICUDPStream(t *testing.T) {
	for _, target := range []string{"cdn.example:443", "203.0.113.7:443", "[2001:db8::1]:443"} {
		if !preferQUICUDPStream(target) {
			t.Errorf("HTTP/3 target missed: %s", target)
		}
	}
	for _, target := range []string{"cdn.example:4443", "1.1.1.1:53", "host:3478", "bad"} {
		if preferQUICUDPStream(target) {
			t.Errorf("unrelated UDP transport changed: %s", target)
		}
	}
}

func TestSizeFailureIsNotNetworkBlocking(t *testing.T) {
	sizeError := &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
	if !isQUICDatagramTooLarge(fmt.Errorf("wrapped: %w", sizeError)) {
		t.Fatal("size failure not classified")
	}
	for _, err := range []error{nil, errors.New("timeout"), errors.New("too large")} {
		if isQUICDatagramTooLarge(err) {
			t.Fatalf("non-size failure misclassified: %v", err)
		}
	}
}
