package main

import (
	"encoding/hex"
	"strconv"
	"time"
)

func realityReplayKey(version int, token, pub []byte) string {
	return "wire" + strconv.Itoa(version) + ":" + hex.EncodeToString(token) + hex.EncodeToString(pub)
}

const maxReplayTokens = 100000

func authTokenUsed(token string) bool {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	_, exists := usedTokens[token]
	return exists
}

// Only called after cryptographic verification. Never evict a still-live
// replay record to admit a new one: fail closed when the finite cache is full.
func consumeAuthToken(token string) bool {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	if _, exists := usedTokens[token]; exists || len(usedTokens) >= maxReplayTokens {
		return false
	}
	usedTokens[token] = time.Now()
	return true
}
