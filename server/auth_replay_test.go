package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func isolateReplay(t *testing.T) {
	t.Helper()
	tokenMutex.Lock()
	before := usedTokens
	usedTokens = make(map[string]time.Time)
	tokenMutex.Unlock()
	t.Cleanup(func() { tokenMutex.Lock(); usedTokens = before; tokenMutex.Unlock() })
}

func TestReplayCacheBoundAndConcurrentSingleUse(t *testing.T) {
	isolateReplay(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if consumeAuthToken("same") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("replay admitted concurrently")
	}
	for i := 1; i < maxReplayTokens; i++ {
		if !consumeAuthToken(fmt.Sprint(i)) {
			t.Fatal("premature full")
		}
	}
	if consumeAuthToken("overflow") || len(usedTokens) != maxReplayTokens || consumeAuthToken("same") {
		t.Fatal("cache overflow or eviction")
	}
}

func sessionFixture(timestamp uint32, pub []byte, key []byte) []byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[:4], timestamp)
	nonce[4] = 91
	token := make([]byte, 32)
	nonceMask := sha256.Sum256(append([]byte("atlant-nonce-v3"), pub...))
	for i := 0; i < 4; i++ {
		token[i+4] = nonce[i] ^ nonceMask[i]
	}
	copy(token[8:16], nonce[4:])
	tag := sha256.Sum256([]byte("alice"))
	mask := sha256.Sum256(append(nonce[:], pub...))
	for i := 0; i < 4; i++ {
		token[i] = tag[i] ^ mask[i]
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce[:])
	mac.Write(pub)
	copy(token[16:], mac.Sum(nil)[:16])
	return token
}

func TestSessionTimestampCannotBypassWindowWithOutOfRangeValue(t *testing.T) {
	isolateUsers(t)
	isolateReplay(t)
	key, _ := hex.DecodeString(strings.Repeat("ab", 32))
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: hex.EncodeToString(key), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	pub := make([]byte, 32)
	pub[0] = 9
	for _, ts := range []uint32{0, 1, 1699999999, 2050000001, ^uint32(0), uint32(time.Now().Unix() - 181), uint32(time.Now().Unix() + 181)} {
		if _, _, _, _, _, ok := authenticateSessionID(sessionFixture(ts, pub, key), pub); ok {
			t.Fatalf("timestamp accepted %d", ts)
		}
	}
	token := sessionFixture(uint32(time.Now().Unix()), pub, key)
	if _, _, _, _, _, ok := authenticateSessionID(token, pub); !ok {
		t.Fatal("valid token rejected")
	}
	if _, _, _, _, _, ok := authenticateSessionID(token, pub); ok {
		t.Fatal("replay accepted")
	}
}
