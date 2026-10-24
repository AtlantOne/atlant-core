package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestDestinationDialEscapesBlackHoledFirstIP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var lookups atomic.Int32
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		lookups.Add(1)
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1"), net.ParseIP("127.0.0.1")}, nil
	}
	peer, remote := net.Pipe()
	defer remote.Close()
	firstCanceled := make(chan struct{})
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case "8.8.8.8:443":
			<-ctx.Done()
			close(firstCanceled)
			return nil, ctx.Err()
		case "1.1.1.1:443":
			return peer, nil
		default:
			t.Errorf("unverified address dialed: %s", addr)
			return nil, errors.New("unsafe")
		}
	}
	conn, err := dialPublicTCP(ctx, "cdn.example:443", lookup, dial)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if lookups.Load() != 1 {
		t.Fatal("destination was resolved more than once")
	}
	select {
	case <-firstCanceled:
	case <-ctx.Done():
		t.Fatal("losing dial was not canceled")
	}
}

func TestDestinationDialRejectsPrivateAndBoundsDNS(t *testing.T) {
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Error("private address dialed")
		return nil, errors.New("unsafe")
	}
	if _, err := dialPublicTCP(context.Background(), "internal.example:443", lookup, dial); err == nil {
		t.Fatal("private addresses accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	lookup = func(ctx context.Context, _, _ string) ([]net.IP, error) { <-ctx.Done(); return nil, ctx.Err() }
	if _, err := dialPublicTCP(ctx, "slow.example:443", lookup, dial); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS not bounded: %v", err)
	}
}

func TestDestinationDialTriesAllValidatedAddresses(t *testing.T) {
	var attempts atomic.Int32
	failure := errors.New("refused")
	lookup := func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1"), net.ParseIP("8.8.8.8")}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { attempts.Add(1); return nil, failure }
	_, err := dialPublicTCP(context.Background(), "cdn.example:443", lookup, dial)
	if !errors.Is(err, failure) || attempts.Load() != 2 {
		t.Fatalf("attempts=%d err=%v", attempts.Load(), err)
	}
}
