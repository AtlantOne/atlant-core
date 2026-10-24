package quicpeer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/quic-go/quic-go"
	"sync"
	"time"
)

// CIDGenerator keeps the existing 20-byte classification format, adding a
// random starting nonce and a per-transport counter so IDs don't repeat in
// the same second. TLS-bound mutual authentication remains mandatory.
type CIDGenerator struct {
	mu          sync.Mutex
	tag         [4]byte
	key         []byte
	initialized bool
	nonce       uint32
}

func NewCIDGenerator(user string, key []byte) *CIDGenerator {
	digest := sha256.Sum256([]byte(user))
	return &CIDGenerator{tag: [4]byte(digest[:4]), key: append([]byte(nil), key...)}
}

func (*CIDGenerator) ConnectionIDLen() int { return 20 }

func (g *CIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.key) != 32 {
		return quic.ConnectionID{}, fmt.Errorf("CID key must be 32 bytes")
	}
	if !g.initialized {
		var seed [4]byte
		if _, err := rand.Read(seed[:]); err != nil {
			return quic.ConnectionID{}, err
		}
		g.nonce = binary.BigEndian.Uint32(seed[:])
		g.initialized = true
	}
	g.nonce++
	var cid [20]byte
	binary.BigEndian.PutUint32(cid[8:12], g.nonce)
	mask := cidTagMask(cid[8:12])
	for i := 0; i < 4; i++ {
		cid[i] = g.tag[i] ^ mask[i]
	}
	tsInput := append(append([]byte{}, g.key...), cid[8:12]...)
	tsMask := sha256.Sum256(tsInput)
	binary.BigEndian.PutUint32(cid[4:8], uint32(time.Now().Unix())^binary.BigEndian.Uint32(tsMask[:4]))
	mac := hmac.New(sha256.New, g.key)
	_, _ = mac.Write(cid[:12])
	copy(cid[12:], mac.Sum(nil)[:8])
	return quic.ConnectionIDFromBytes(cid[:]), nil
}

func cidTagMask(nonce []byte) [32]byte {
	input := make([]byte, 0, 4+len("atlant-quic-v3"))
	input = append(input, nonce...)
	input = append(input, []byte("atlant-quic-v3")...)
	return sha256.Sum256(input)
}

func CIDUserTag(cid []byte) ([4]byte, bool) {
	var tag [4]byte
	if len(cid) != 20 {
		return tag, false
	}
	mask := cidTagMask(cid[8:12])
	for i := range tag {
		tag[i] = cid[i] ^ mask[i]
	}
	return tag, true
}

func VerifyCID(cid, key []byte, now time.Time) bool {
	if len(cid) != 20 || len(key) != 32 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(cid[:12])
	if !hmac.Equal(cid[12:], mac.Sum(nil)[:8]) {
		return false
	}
	tsInput := append(append([]byte{}, key...), cid[8:12]...)
	mask := sha256.Sum256(tsInput)
	ts := binary.BigEndian.Uint32(cid[4:8]) ^ binary.BigEndian.Uint32(mask[:4])
	delta := now.Unix() - int64(ts)
	return delta >= -180 && delta <= 180
}
