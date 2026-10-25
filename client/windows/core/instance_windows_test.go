package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestTUNInstanceExclusionAndRelease(t *testing.T) {
	name := fmt.Sprintf(`Local\AtlantTUN-Test-%d`, time.Now().UnixNano())
	release, err := acquireTUNInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireTUNInstance(name); err == nil {
		other()
		release()
		t.Fatal("duplicate TUN allowed")
	}
	release()
	release, err = acquireTUNInstance(name)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestSOCKSListenerConflictAndRelease(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	cfg := &Config{LocalPort: occupied.Addr().String()}
	if _, listener, err := openSocks5(cfg); err == nil {
		listener.Close()
		t.Fatal("occupied proxy port accepted")
	}
	occupied.Close()
	_, listener, err := openSocks5(cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
}
