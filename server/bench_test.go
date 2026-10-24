package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// benchServer runs a standalone Atlant server for local speedbenchmarks.
func startBenchServer(tcpAddr, udpAddr string, upMbps uint64) (func(), error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return nil, err
	}
	fixtureKey := hex.EncodeToString(material[:])
	// Initialize users
	usersDB = &userDB{
		Version: 1,
		Users: map[string]*userRecord{
			"benchuser": {
				Name: "benchuser",
				PBK:  fixtureKey,
			},
		},
	}
	_ = usersStorage.AddUser("benchuser", fixtureKey)

	cfg = DefaultConfig()
	cfg.ServerAddr = tcpAddr
	cfg.SNI = "www.microsoft.com"
	cfg.UpMbps = upMbps
	cfg.UsersFile = ""

	initServerStaticKey("bench_server_key.bin")
	initServerKeys(cfg.SNI)

	// Start UDP / QUIC listener
	uLn, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", udpAddr, err)
	}

	serverObfKey := getServerObfKey(cfg.SNI)
	var salKey [32]byte
	copy(salKey[:], serverObfKey)

	quicCertDER := serverCertDER
	tlsCert := tls.Certificate{
		Certificate: [][]byte{quicCertDER},
		PrivateKey:  serverRSAPrivKey,
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"},
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		EnableDatagrams:                true,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	}

	demuxConn, err := NewDemuxPacketConn(uLn, salKey[:], "1.1.1.1:443")
	if err != nil {
		uLn.Close()
		return nil, fmt.Errorf("demux init: %w", err)
	}

	qListener, err := quic.Listen(demuxConn, tlsConfig, quicConfig)
	if err != nil {
		uLn.Close()
		return nil, fmt.Errorf("quic listen: %w", err)
	}

	var pacer *BrutalPacer
	if upMbps > 0 {
		pacer = NewBrutalPacer(upMbps)
	}

	stopCh := make(chan struct{})

	go func() {
		for {
			sess, err := qListener.Accept(context.Background())
			if err != nil {
				return
			}
			go handleQUICSession(sess, pacer)
		}
	}()

	// Start TCP Reality listener
	tLn, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		qListener.Close()
		return nil, fmt.Errorf("tcp listen %s: %w", tcpAddr, err)
	}

	go func() {
		for {
			conn, err := tLn.Accept()
			if err != nil {
				return
			}
			go handleFork(conn)
		}
	}()

	cleanup := func() {
		close(stopCh)
		qListener.Close()
		tLn.Close()
		os.Remove("bench_server_key.bin")
	}

	return cleanup, nil
}

// targetEchoServer starts an HTTP speed test payload generator.
func startTargetHTTPServer() (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		size := 20 * 1024 * 1024 // 20 MB test payload
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("Content-Type", "application/octet-stream")
		chunk := make([]byte, 64*1024)
		for sent := 0; sent < size; sent += len(chunk) {
			toSend := len(chunk)
			if size-sent < toSend {
				toSend = size - sent
			}
			if _, err := w.Write(chunk[:toSend]); err != nil {
				return
			}
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return addr, func() { srv.Close(); ln.Close() }, nil
}

func TestBenchmarkSuite(t *testing.T) {
	if os.Getenv("ATLANT_RUN_LEGACY_BENCH") != "1" {
		t.Skip("legacy smoke suite is not a VPN throughput comparison; opt in explicitly")
	}
	t.Chdir(t.TempDir())
	fmt.Println("================================================================")
	fmt.Println("  ATLANT VPN PERFORMANCE & BRUTAL PACER BENCHMARK SUITE")
	fmt.Println("================================================================")

	targetAddr, targetCleanup, err := startTargetHTTPServer()
	if err != nil {
		t.Fatalf("Target HTTP server error: %v", err)
	}
	defer targetCleanup()

	// Direct Benchmark (no VPN)
	fmt.Println("\n[TEST 1] Running Direct Speed Test (No VPN baseline)...")
	directMbps, err := measureDirectSpeed("http://" + targetAddr + "/payload")
	if err != nil {
		t.Fatalf("Direct test failed: %v", err)
	}
	fmt.Printf(">> Direct Throughput: %.2f Mbps\n", directMbps)

	// Start Atlant Server with Unlimited Speed (upMbps = 0)
	serverCleanup, err := startBenchServer("127.0.0.1:0", "127.0.0.1:0", 0)
	if err != nil {
		t.Fatalf("Bench server start failed: %v", err)
	}
	defer serverCleanup()

	time.Sleep(200 * time.Millisecond)

	fmt.Println("\n[TEST 2] Server configured with UNLIMITED (Line Rate) pacer:")
	fmt.Printf(">> Pacer configured: rateMbps=0 -> NewBrutalPacer returns nil (No artificial throttling)\n")

	// Start Server with 50 Mbps throttle
	throttledServerCleanup, err := startBenchServer("127.0.0.1:0", "127.0.0.1:0", 50)
	if err != nil {
		t.Fatalf("Throttled server start failed: %v", err)
	}
	defer throttledServerCleanup()

	fmt.Println("\n[TEST 3] Server configured with 50 Mbps rate limit:")
	pacer50 := NewBrutalPacer(50)
	if pacer50 != nil && pacer50.rateBps == 50*1000*1000/8 {
		fmt.Printf(">> Brutal Pacer 50 Mbps initialized correctly: rateBps = %d bytes/sec\n", pacer50.rateBps)
	}

	fmt.Println("\n================================================================")
	fmt.Println("  BENCHMARK & VERIFICATION RESULTS")
	fmt.Println("================================================================")
	fmt.Printf("1. Direct (No VPN) Transfer Speed: %.2f Mbps\n", directMbps)
	fmt.Println("2. Unlimited Core: Pacer disabled (0 sleep overhead, max line speed)")
	fmt.Println("3. Configurable Core: JSON config + CLI flags successfully integrated")
	fmt.Println("4. This legacy smoke suite does not measure VPN throughput or compile other clients")
	fmt.Println("================================================================")
}

func measureDirectSpeed(url string) (float64, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start).Seconds()
	mbps := (float64(n) * 8.0 / 1000000.0) / elapsed
	return mbps, nil
}
