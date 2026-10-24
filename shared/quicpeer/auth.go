package quicpeer

import (
	"atlant.local/protocol/auth"
	"context"
	"fmt"
	"github.com/quic-go/quic-go"
	"time"
)

func prepare(ctx context.Context, stream ClientStream) func() {
	deadline := time.Now().Add(5 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(0x100); stream.CancelWrite(0x100) })
	return func() { stop(); stream.CancelRead(0); _ = stream.Close() }
}

func Client(ctx context.Context, conn *quic.Conn, user string, key []byte) error {
	binding, err := auth.Binding(conn.ConnectionState().TLS)
	if err != nil {
		return err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer prepare(ctx, stream)()
	if err := auth.Client(stream, user, key, binding); err != nil {
		return fmt.Errorf("%w: %v", auth.ErrAuthentication, err)
	}
	return nil
}

func Server(ctx context.Context, conn *quic.Conn, lookup func(string) ([]byte, bool)) (string, error) {
	binding, err := auth.Binding(conn.ConnectionState().TLS)
	if err != nil {
		return "", err
	}
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return "", err
	}
	defer prepare(ctx, stream)()
	return auth.Server(stream, binding, lookup)
}
