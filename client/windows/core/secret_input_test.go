package main

import (
	"io"
	"strings"
	"testing"
)

func TestPrivatePBKInputDoesNotConsumeStop(t *testing.T) {
	key := strings.Repeat("a", 64)
	input := strings.NewReader(key + "\nSTOP\n")
	got, err := readPBKFromPipe(input)
	if err != nil || got != key {
		t.Fatal("private key not read")
	}
	remaining, _ := io.ReadAll(input)
	if string(remaining) != "STOP\n" {
		t.Fatal("control command prefetched")
	}
}

func TestPrivatePBKInputRejectsMalformedKeys(t *testing.T) {
	for _, s := range []string{"short\n", strings.Repeat("g", 64) + "\n", strings.Repeat("a", 64) + "x"} {
		if _, err := readPBKFromPipe(strings.NewReader(s)); err == nil {
			t.Fatal("invalid private input accepted")
		}
	}
}
