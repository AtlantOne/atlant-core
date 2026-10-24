package quicadmission

import (
	"atlant.local/protocol/wire"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"time"
)

const BootstrapBatchSize = 32

// Wire4's existing batch framing is fixed at 32. Quota reclamation belongs in
// the store; changing this count would silently break deployed wire4 peers.
const BoundBatchSize = 32

// Wire6 only needs one private token per attempt; public client CIDs stay empty.
const Wire6BatchSize = 1

func batchSize(version byte) int {
	if version == 6 {
		return Wire6BatchSize
	}
	if version == 4 {
		return BoundBatchSize
	}
	return BootstrapBatchSize
}

// FetchPool owns an already mutually authenticated REALITY 3.x connection.
// A NEW connection and batch is used per QUIC attempt, never persisted,
// restored or retried. Crash/reinstall cannot resurrect an exposed CID.
// Server restart loses issuance and requires rebootstrap, never downgrade.
func FetchPool(ctx context.Context, conn net.Conn) (*CIDPool, error) {
	defer conn.Close()
	deadline := time.Now().Add(10 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	return fetchPool(conn, 3)
}

func fetchPool(conn net.Conn, version byte) (*CIDPool, error) {
	opcode := byte(0x13)
	if version == 4 {
		opcode = 0x14
	}
	if version == 6 {
		opcode = 0x15
	}
	if err := wire.WriteFull(conn, []byte{opcode, 0, 0, 0}); err != nil {
		return nil, errors.New("REALITY CID request failed; no legacy fallback")
	}
	var header [13]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, errors.New("REALITY CID response failed; no legacy fallback")
	}
	count := int(binary.BigEndian.Uint16(header[1:3]))
	expires := int64(binary.BigEndian.Uint64(header[3:11]))
	padding := int(binary.BigEndian.Uint16(header[11:13]))
	if header[0] != version || count != batchSize(version) || expires <= time.Now().Unix() || expires > time.Now().Add(time.Hour).Unix() || padding > 512 {
		return nil, ErrRejected
	}
	tokens := make([]Token, count)
	for i := range tokens {
		if _, err := io.ReadFull(conn, tokens[i][:]); err != nil {
			return nil, ErrRejected
		}
	}
	if _, err := io.CopyN(io.Discard, conn, int64(padding)); err != nil {
		return nil, ErrRejected
	}
	return NewCIDPool(tokens)
}

// WriteBatch is only called inside mutually authenticated REALITY 3.x.
func WriteBatch(w io.Writer, batch Batch) error {
	return WriteBatchVersion(w, batch, 3)
}

func WriteBatchVersion(w io.Writer, batch Batch, version byte) error {
	if version != 3 && version != 4 && version != 6 {
		return ErrOptions
	}
	if len(batch.Tokens) != batchSize(version) {
		return ErrOptions
	}
	n, err := rand.Int(rand.Reader, big.NewInt(225))
	if err != nil {
		return err
	}
	padding := 32 + int(n.Int64())
	frame := make([]byte, 13+TokenSize*len(batch.Tokens)+padding)
	frame[0] = version
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(batch.Tokens)))
	binary.BigEndian.PutUint64(frame[3:11], uint64(batch.Expires.Unix()))
	binary.BigEndian.PutUint16(frame[11:13], uint16(padding))
	for i, token := range batch.Tokens {
		copy(frame[13+i*TokenSize:], token[:])
	}
	if _, err := io.ReadFull(rand.Reader, frame[len(frame)-padding:]); err != nil {
		return err
	}
	return wire.WriteFull(w, frame)
}
