package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func isSpeedtestAddr(addr string) bool {
	lower := strings.ToLower(strings.TrimSpace(addr))
	return lower == "speedtest:80" ||
		lower == "speedtest:443" ||
		lower == "speedtest" ||
		lower == "__speedtest__" ||
		lower == "speedtest.internal:80" ||
		lower == "speedtest.internal" ||
		lower == "speedtest.atlant:80" ||
		lower == "speedtest.atlant"
}

type streamConn interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// handleSpeedtestStream conducts real in-tunnel throughput, latency and jitter measurements
// directly over whichever transport is in use (Reality TCP, QUIC, or XHTTP).
func handleSpeedtestStream(conn streamConn, user string) {
	defer conn.Close()
	remoteStr := "stream"
	if ra, ok := conn.(interface{ RemoteAddr() net.Addr }); ok && ra.RemoteAddr() != nil {
		remoteStr = ra.RemoteAddr().String()
	}
	log.Printf("[SPEEDTEST] In-tunnel session started for user '%s' (%s)", user, remoteStr)

	reader := bufio.NewReader(conn)
	// Pre-fill a 64KB dummy buffer for high-speed download throughput generation
	dummyBuf := make([]byte, 64*1024)
	_, _ = rand.Read(dummyBuf)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		lineBytes, err := reader.ReadSlice('\n')
		if err != nil {
			return
		}
		line := string(lineBytes)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "PING":
			// PING <id> <timestamp_ns> -> PONG <id> <timestamp_ns>
			resp := "PONG"
			if len(parts) > 1 {
				resp += " " + strings.Join(parts[1:], " ")
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(resp + "\n")); err != nil {
				return
			}

		case "DOWNLOAD":
			// DOWNLOAD <bytes>
			targetBytes := int64(25 * 1024 * 1024) // Default 25 MB
			if len(parts) > 1 {
				if parsed, err := strconv.ParseInt(parts[1], 10, 64); err == nil && parsed > 0 {
					// Safety cap at 200 MB per test
					if parsed > 200*1024*1024 {
						parsed = 200 * 1024 * 1024
					}
					targetBytes = parsed
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(conn, "START %d\n", targetBytes); err != nil {
				return
			}

			sent := int64(0)
			for sent < targetBytes {
				toSend := int64(len(dummyBuf))
				if targetBytes-sent < toSend {
					toSend = targetBytes - sent
				}
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if user != "" && !recordUserTraffic(user, 0, uint64(toSend)) {
					return
				}
				n, wErr := conn.Write(dummyBuf[:toSend])
				if n > 0 {
					sent += int64(n)
				}
				if wErr != nil {
					return
				}
			}

		case "UPLOAD":
			// UPLOAD <bytes>
			targetBytes := int64(10 * 1024 * 1024) // Default 10 MB
			if len(parts) > 1 {
				if parsed, err := strconv.ParseInt(parts[1], 10, 64); err == nil && parsed > 0 {
					if parsed > 200*1024*1024 {
						parsed = 200 * 1024 * 1024
					}
					targetBytes = parsed
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintf(conn, "START %d\n", targetBytes); err != nil {
				return
			}

			start := time.Now()
			recv := int64(0)
			buf := make([]byte, 64*1024)
			for recv < targetBytes {
				toRead := int64(len(buf))
				if targetBytes-recv < toRead {
					toRead = targetBytes - recv
				}
				_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
				n, rErr := reader.Read(buf[:toRead])
				if n > 0 {
					recv += int64(n)
					if user != "" {
						if !recordUserTraffic(user, uint64(n), 0) {
							return
						}
					}
				}
				if rErr != nil {
					break
				}
			}
			elapsedMs := time.Since(start).Milliseconds()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprintf(conn, "DONE %d %d\n", recv, elapsedMs)

		case "QUIT":
			return

		default:
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte("ERROR unknown_command\n"))
		}
	}
}
