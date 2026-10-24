package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func liveEnvironmentConfig() (*Config, error) {
	version, err := strconv.Atoi(os.Getenv("ATLANT_TEST_WIRE_VERSION"))
	if err != nil || (version != 2 && version != 3 && version != 4 && version != 6 && version != 7) {
		return nil, fmt.Errorf("set ATLANT_TEST_WIRE_VERSION explicitly to 2, 3, 4, 6 or 7")
	}
	cfg := &Config{
		ServerAddr: os.Getenv("ATLANT_TEST_SERVER"), SNI: os.Getenv("ATLANT_TEST_SNI"),
		PBK: os.Getenv("ATLANT_TEST_PBK"), ServerPubKey: os.Getenv("ATLANT_TEST_SERVER_PUBKEY"),
		User: os.Getenv("ATLANT_TEST_USER"), Fingerprint: "chrome", Path: "/api/v1/sync", WireVersion: version,
	}
	if cfg.ServerAddr == "" || cfg.PBK == "" || cfg.User == "" || cfg.ServerPubKey == "" {
		return nil, fmt.Errorf("live environment profile requires server, PBK, user and pinned server public key")
	}
	if value := os.Getenv("ATLANT_TEST_FINGERPRINT"); value != "" {
		cfg.Fingerprint = value
	}
	return cfg, nil
}

func getTestConfig(t *testing.T) *Config {
	t.Helper()
	if os.Getenv("ATLANT_RUN_LIVE") != "1" && os.Getenv("ATLANT_TEST_SERVER") == "" && os.Getenv("ATLANT_TEST_CONFIG") == "" {
		t.Skip("set ATLANT_RUN_LIVE=1 to run live checks; QUIC requires the upgraded server")
	}
	if path := os.Getenv("ATLANT_TEST_CONFIG"); path != "" {
		cfg := loadConfigFromFile(path)
		if cfg == nil {
			t.Fatal("cannot load explicitly selected live profile")
		}
		return cfg
	}
	if os.Getenv("ATLANT_TEST_SERVER") == "" {
		if fileCfg := loadConfigFromFile("atlant_config.json"); fileCfg != nil {
			return fileCfg
		}
		if fileCfg := loadConfigFromFile("../../../atlant_config.json"); fileCfg != nil {
			return fileCfg
		}
		t.Fatal("no live profile; set ATLANT_TEST_CONFIG or explicit environment credentials and wire version")
	}
	cfg, err := liveEnvironmentConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func selectLiveEgress(t *testing.T) {
	t.Helper()
	if os.Getenv("ATLANT_TEST_DEFAULT_ROUTE") == "1" {
		physicalLocalIP = nil
		t.Log("egress: default OS route (may traverse another VPN)")
		return
	}
	if physicalLocalIP == nil {
		_, physIP, _ := getDefaultGateway("")
		if physIP != "" {
			physicalLocalIP = net.ParseIP(physIP)
		}
	}
	t.Logf("egress: physical source IP %v", physicalLocalIP)
}

func TestLiveXHTTP(t *testing.T) {
	selectLiveEgress(t)
	cfg := getTestConfig(t)

	t.Logf("Dialing %s via XHTTP over REALITY...", cfg.ServerAddr)
	conn, err := dialXHTTPStream(cfg, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dialXHTTPStream failed: %v", err)
	}
	defer conn.Close()
	checkLiveHTTP(t, conn)
}

func checkLiveHTTP(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Received response: %s (Proto: %s)", resp.Status, resp.Proto)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 {
		t.Fatalf("invalid HTTP response body: bytes=%d err=%v", len(body), err)
	}
	t.Logf("HTTP 200 and %d body bytes received through tunnel", len(body))
}

func TestLiveQUIC(t *testing.T) {
	selectLiveEgress(t)
	cfg := getTestConfig(t)

	t.Logf("Dialing %s via QUIC (wire=%d)...", cfg.ServerAddr, cfg.WireVersion)
	conn, err := dialQUICStream(cfg, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dialQUICStream failed: %v", err)
	}
	defer conn.Close()
	checkLiveHTTP(t, conn)
}

func TestLiveRealityTCP(t *testing.T) {
	selectLiveEgress(t)
	cfg := getTestConfig(t)
	t.Logf("Dialing %s via TCP REALITY (SNI=%s)...", cfg.ServerAddr, cfg.SNI)
	conn, err := dialRemoteRealityStream(cfg, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("dialRealityConn failed: %v", err)
	}
	defer conn.Close()
	checkLiveHTTP(t, conn)
}

func TestLiveEnvironmentRequiresExplicitWire(t *testing.T) {
	t.Setenv("ATLANT_TEST_FINGERPRINT", "")
	for _, value := range []string{"", "0", "5", "8", "garbage"} {
		t.Setenv("ATLANT_TEST_WIRE_VERSION", value)
		if _, err := liveEnvironmentConfig(); err == nil {
			t.Fatalf("accepted invalid or implicit wire %q", value)
		}
	}
	for _, key := range []string{"SERVER", "PBK", "USER", "SERVER_PUBKEY"} {
		t.Setenv("ATLANT_TEST_"+key, "fixture")
	}
	for _, version := range []int{2, 3, 4, 6, 7} {
		t.Setenv("ATLANT_TEST_WIRE_VERSION", strconv.Itoa(version))
		cfg, err := liveEnvironmentConfig()
		if err != nil || cfg.WireVersion != version || cfg.Fingerprint != "chrome" {
			t.Fatalf("wire %d: cfg=%v err=%v", version, cfg != nil, err)
		}
	}
	t.Setenv("ATLANT_TEST_PBK", "")
	if _, err := liveEnvironmentConfig(); err == nil {
		t.Fatal("accepted incomplete credentials")
	}
}
