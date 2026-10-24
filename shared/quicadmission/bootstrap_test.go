package quicadmission

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestRealityBootstrapPoolIsFreshFiniteAndNoHTTPEndpoint(t *testing.T) {
	s := testStore(t, 128, 128)
	var first Token
	for i := 0; i < 2; i++ {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var request [4]byte
			if _, err := io.ReadFull(server, request[:]); err != nil || request != [4]byte{0x13, 0, 0, 0} {
				return
			}
			b, err := s.Issue("alice", BootstrapBatchSize)
			if err == nil {
				_ = WriteBatch(server, b)
			}
		}()
		pool, err := FetchPool(context.Background(), client)
		if err != nil {
			t.Fatal(err)
		}
		cid, err := pool.GenerateConnectionID()
		if err != nil {
			t.Fatal(err)
		}
		token, _ := ParseToken(cid.Bytes())
		if i == 1 && token == first {
			t.Fatal("new attempt reused batch")
		}
		first = token
	}
}
