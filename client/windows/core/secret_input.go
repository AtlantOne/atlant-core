package main

import (
	"encoding/hex"
	"fmt"
	"io"
)

func readPBKFromPipe(reader io.Reader) (string, error) {
	// Read exactly one fixed-size line; do not prefetch a following STOP command.
	var raw [65]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return "", fmt.Errorf("incomplete PBK input")
	}
	if raw[64] != '\n' {
		return "", fmt.Errorf("invalid PBK input size")
	}
	if _, err := hex.DecodeString(string(raw[:64])); err != nil {
		return "", fmt.Errorf("invalid PBK encoding")
	}
	key := string(raw[:64])
	clear(raw[:])
	return key, nil
}
