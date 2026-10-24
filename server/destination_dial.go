package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Resolve once and pass only validated literal addresses to the dialer. Two
// staggered workers allow another CDN address to succeed behind a black hole,
// without one goroutine/socket per address or a second DNS lookup.
func dialPublicTCP(ctx context.Context, target string,
	lookup func(context.Context, string, string) ([]net.IP, error),
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host, port = target, "443"
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = lookup(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve destination: %w", err)
		}
	}
	var v4, v6 []string
	seen := make(map[string]bool)
	for _, ip := range ips {
		if !isSafeIP(ip) {
			continue
		}
		addr := net.JoinHostPort(ip.String(), port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		if ip.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	var addresses []string
	for len(v4) > 0 || len(v6) > 0 {
		if len(v4) > 0 {
			addresses = append(addresses, v4[0])
			v4 = v4[1:]
		}
		if len(v6) > 0 {
			addresses = append(addresses, v6[0])
			v6 = v6[1:]
		}
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no permitted destination addresses")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan string, len(addresses))
	for _, addr := range addresses {
		jobs <- addr
	}
	close(jobs)
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	workers := min(2, len(addresses))
	var attemptBudget time.Duration
	if deadline, ok := ctx.Deadline(); ok && len(addresses) > workers {
		// Reserve time for later addresses even if both first attempts stall.
		rounds := (len(addresses) + workers - 1) / workers
		attemptBudget = max(time.Nanosecond, (time.Until(deadline)-250*time.Millisecond)/time.Duration(rounds))
	}
	for i := 0; i < workers; i++ {
		go func(delayed bool) {
			if delayed {
				timer := time.NewTimer(250 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
			}
			var failures []error
			for addr := range jobs {
				if ctx.Err() != nil {
					return
				}
				attemptCtx := ctx
				stopAttempt := func() {}
				if attemptBudget > 0 {
					attemptCtx, stopAttempt = context.WithTimeout(ctx, attemptBudget)
				}
				conn, err := dial(attemptCtx, "tcp", addr)
				stopAttempt()
				if err == nil {
					select {
					case results <- result{conn: conn}:
					case <-ctx.Done():
						_ = conn.Close()
					}
					return
				}
				failures = append(failures, err)
			}
			select {
			case results <- result{err: errors.Join(failures...)}:
			case <-ctx.Done():
			}
		}(i > 0)
	}
	var failures []error
	for i := 0; i < workers; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-results:
			if r.conn != nil {
				return r.conn, nil
			}
			if r.err != nil {
				failures = append(failures, r.err)
			}
		}
	}
	return nil, fmt.Errorf("all permitted destination addresses failed: %w", errors.Join(failures...))
}
