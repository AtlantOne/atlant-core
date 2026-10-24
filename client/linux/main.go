package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
)

func main() {
	cfg := parseConfig()
	initLogging(cfg.LogLevel)
	if cfg.Tun {
		resolved, err := prepareTunEndpoints(cfg)
		if err != nil {
			log.Printf("[TUN] Startup refused: %v", err)
			return
		}
		cfg = resolved
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("[ATLANT-LINUX] Starting client for server %s (SNI: %s, User: %s, Transport: %s, Fingerprint: %s)",
		cfg.ServerAddr, cfg.SNI, cfg.User, cfg.Transport, cfg.Fingerprint)

	// Start background Chaffing worker if enabled
	if cfg.ChaffingEnabled {
		go startChaffingWorker(ctx, cfg)
	}

	tunErrors := make(chan error, 1)
	tunDone := make(chan struct{})
	if cfg.Tun {
		log.Printf("[ATLANT-LINUX] Enabling TUN VPN mode on %s...", cfg.TunName)
		ready := make(chan struct{})
		go func() { defer close(tunDone); tunErrors <- startTun(ctx, cfg, func() { close(ready) }) }()
		defer func() {
			cancel()
			select {
			case <-tunDone:
			case <-time.After(5 * time.Second):
				log.Print("[TUN] Cleanup timeout; inspect owned protection rules")
			}
		}()
		select {
		case <-ready:
		case err := <-tunErrors:
			log.Printf("[TUN] Startup refused: %v", err)
			return
		}
	}

	// Always launch SOCKS5 proxy
	socksServer, err := socks5.New(&socks5.Config{
		Dial: func(c context.Context, network, addr string) (net.Conn, error) {
			return dialRemote(cfg, network, addr)
		},
	})
	if err != nil {
		log.Printf("[SOCKS5] Failed to initialize SOCKS5 server: %v", err)
		return
	}

	host, _, bindErr := net.SplitHostPort(cfg.LocalPort)
	ip := net.ParseIP(host)
	if bindErr != nil || ip == nil || !ip.IsLoopback() {
		log.Print("[SOCKS5] Refusing unauthenticated non-loopback proxy")
		return
	}
	ln, err := net.Listen("tcp", cfg.LocalPort)
	if err != nil {
		log.Printf("[SOCKS5] Failed to listen on %s: %v", cfg.LocalPort, err)
		return
	}
	defer ln.Close()

	log.Printf("[SOCKS5] Local SOCKS5 proxy listening on %s (route via Reality/XHTTP/QUIC)", ln.Addr())
	go func() {
		if err := socksServer.Serve(ln); err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[SOCKS5] Serve error: %v", err)
			}
		}
	}()

	fmt.Printf("\n✓ Atlant VPN Linux Client is running!\n")
	fmt.Printf("  • Server: %s (SNI: %s)\n", cfg.ServerAddr, cfg.SNI)
	fmt.Printf("  • SOCKS5 Proxy: %s\n", ln.Addr())
	if cfg.Tun {
		fmt.Printf("  • TUN VPN Adapter: %s (%s)\n", cfg.TunName, cfg.TunAddr)
	}
	fmt.Printf("  • Press Ctrl+C to terminate\n\n")

	select {
	case <-sigCh:
	case err := <-tunErrors:
		log.Printf("[TUN] Unexpected stop: %v", err)
	}
	log.Println("[SHUTDOWN] Signal received, shutting down Atlant VPN client...")
	cancel()
	time.Sleep(500 * time.Millisecond)
	log.Println("[SHUTDOWN] Exited cleanly.")
}
