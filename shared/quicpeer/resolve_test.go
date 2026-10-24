package quicpeer

import (
	"context"
	"errors"
	"testing"
)

func TestQUICEndpointResolutionCancellationAndLiterals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveUDP(ctx, "127.0.0.1:443"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"127.0.0.1:443", "[::1]:443"} {
		address, err := ResolveUDP(context.Background(), endpoint)
		if err != nil || address.Port != 443 {
			t.Fatal(endpoint, address, err)
		}
	}
	for _, endpoint := range []string{"localhost:0", "localhost:65536", "missing-port"} {
		if _, err := ResolveUDP(context.Background(), endpoint); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
}
