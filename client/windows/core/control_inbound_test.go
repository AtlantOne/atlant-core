package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Invoked by the server's local multi-inbound test in a separate process so
// client session pools cannot accidentally reuse another fixture's profile.
func TestLocalControlInboundProbe(t *testing.T) {
	if os.Getenv("ATLANT_LOCAL_INBOUND_PROBE") != "1" {
		t.Skip("local server fixture required")
	}
	cfg, err := liveEnvironmentConfig()
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("local inbound probe requires a literal loopback server")
	}
	probe := func() error {
		var conn net.Conn
		var err error
		switch os.Getenv("ATLANT_LOCAL_INBOUND_TRANSPORT") {
		case "tcp", "mux":
			cfg.Mux = os.Getenv("ATLANT_LOCAL_INBOUND_TRANSPORT") == "mux"
			conn, err = dialRemoteRealityStream(cfg, "tcp", "speedtest:80")
		case "xhttp":
			cfg.Path = os.Getenv("ATLANT_LOCAL_INBOUND_PATH")
			conn, err = dialXHTTPStream(cfg, "tcp", "speedtest:80")
		default:
			return fmt.Errorf("unknown local transport")
		}
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(conn, "PING local-inbound\n"); err != nil {
			return err
		}
		reply, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return err
		}
		if reply != "PONG local-inbound\n" {
			return fmt.Errorf("unexpected local reply %q", reply)
		}
		return nil
	}
	err = probe()
	if os.Getenv("ATLANT_LOCAL_INBOUND_EXPECT") == "deny" {
		if err == nil {
			t.Fatal("disabled transport or wrong XHTTP path accepted a stream")
		}
	} else if err != nil {
		t.Fatal(err)
	}
}
