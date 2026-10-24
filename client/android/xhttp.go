//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"atlant.local/protocol/wire"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const xhttpPoolSize = 3

var (
	xhttpTransports   [xhttpPoolSize]*http2.Transport
	xhttpTrMu         sync.Mutex
	xhttpTransportIdx uint32
	tcpProto          = "tcp" // "tcp" (direct/mux) or "xhttp" (HTTP/2 stream over Reality TLS)
	xhttpPath         = "/api/v1/sync"
	tcpProtoMu        sync.RWMutex
)

// SetTCPProto sets the TCP transport mode: "tcp" (direct/mux) or "xhttp" (HTTP/2 over Reality).
func SetTCPProto(proto string) {
	tcpProtoMu.Lock()
	defer tcpProtoMu.Unlock()
	p := strings.ToLower(strings.TrimSpace(proto))
	if p == "reality" || p == "" {
		p = "tcp"
	}
	tcpProto = p
	log.Printf("[CONFIG] TCP Transport set to: %s", p)
}

// GetTCPProto returns current TCP transport mode.
func GetTCPProto() string {
	tcpProtoMu.RLock()
	defer tcpProtoMu.RUnlock()
	return tcpProto
}

// SetXHTTPPath sets the URL path for XHTTP endpoint (default: /api/v1/sync).
func SetXHTTPPath(path string) {
	tcpProtoMu.Lock()
	defer tcpProtoMu.Unlock()
	p := strings.TrimSpace(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	xhttpPath = p
}

func getXHTTPTransport(cfg *Config) *http2.Transport {
	xhttpTrMu.Lock()
	defer xhttpTrMu.Unlock()

	idx := atomic.AddUint32(&xhttpTransportIdx, 1) % xhttpPoolSize
	if xhttpTransports[idx] != nil {
		return xhttpTransports[idx]
	}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, tlsConfig *tls.Config) (net.Conn, error) {
			// Connect directly via Reality TLS 1.3 channel (XHTTP over Reality)
			secureConn, err := dialRealityConn(cfg)
			if err != nil {
				return nil, fmt.Errorf("reality TLS handshake for XHTTP failed: %w", err)
			}
			if conn, ok := secureConn.(*realitySecureConn); ok {
				conn.enableXHTTPBatching()
			}
			return secureConn, nil
		},
		AllowHTTP:                  true,
		ReadIdleTimeout:            20 * time.Second,
		PingTimeout:                5 * time.Second,
		StrictMaxConcurrentStreams: false,
	}
	xhttpTransports[idx] = tr
	return tr
}

func closeXHTTPTransport() {
	xhttpTrMu.Lock()
	defer xhttpTrMu.Unlock()
	for i := range xhttpTransports {
		if xhttpTransports[i] != nil {
			xhttpTransports[i].CloseIdleConnections()
			xhttpTransports[i] = nil
		}
	}
}

// buildStealthPreamble constructs the binary metadata frame prepended to the POST body.
// Zero headers leak: all routing and auth are inside the encrypted stream payload.
func buildStealthPreamble(pbk, user, network, destAddr string) ([]byte, error) {
	var buf bytes.Buffer

	// Magic (0xA1) + Ver (0x02)
	buf.WriteByte(0xA1)
	buf.WriteByte(0x02)

	// Auth: 8B Timestamp + 8B Nonce + 32B HMAC-SHA256
	var tsNonce [16]byte
	binary.BigEndian.PutUint64(tsNonce[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(tsNonce[8:]); err != nil {
		return nil, err
	}
	buf.Write(tsNonce[:])

	key := parsePBKBytes(pbk)
	mac := hmac.New(sha256.New, key)
	mac.Write(tsNonce[:])
	buf.Write(mac.Sum(nil))

	// Proto: 0x01 (TCP), 0x02 (UDP)
	if strings.ToLower(network) == "udp" {
		buf.WriteByte(0x02)
	} else {
		buf.WriteByte(0x01)
	}

	// Parse host & port
	host, portStr, err := net.SplitHostPort(destAddr)
	if err != nil {
		host = destAddr
		portStr = "80"
	}
	portNum, pErr := strconv.Atoi(portStr)
	if pErr != nil || portNum <= 0 || portNum > 65535 {
		portNum = 80
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	buf.Write(portBytes[:])

	// AddrType & Addr
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(0x01) // IPv4
			buf.Write(ip4)
		} else {
			buf.WriteByte(0x03) // IPv6
			buf.Write(ip.To16())
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name length %d exceeds 255 bytes", len(host))
		}
		buf.WriteByte(0x02) // Domain
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}

	// Pad the encrypted preamble so its length is not fixed by the destination.
	var rnd [1]byte
	_, _ = rand.Read(rnd[:])
	padLen := 16 + int(rnd[0])%64
	var padLenBytes [2]byte
	binary.BigEndian.PutUint16(padLenBytes[:], uint16(padLen))
	buf.Write(padLenBytes[:])

	padData := make([]byte, padLen)
	_, _ = rand.Read(padData)
	buf.Write(padData)

	return buf.Bytes(), nil
}

type lazyHTTP2Reader struct {
	ready chan struct{}
	body  io.ReadCloser
	err   error
}

func (l *lazyHTTP2Reader) Read(p []byte) (int, error) {
	<-l.ready
	if l.err != nil {
		return 0, l.err
	}
	return l.body.Read(p)
}

func (l *lazyHTTP2Reader) Close() error {
	select {
	case <-l.ready:
		if l.body != nil {
			return l.body.Close()
		}
	default:
	}
	return nil
}

func dialXHTTPStream(cfg *Config, network, destAddr string) (net.Conn, error) {
	tr := getXHTTPTransport(cfg)
	pr, pw := io.Pipe()

	tcpProtoMu.RLock()
	targetPath := xhttpPath
	tcpProtoMu.RUnlock()

	targetURL := "https://" + cfg.ServerAddr + targetPath

	preamble, err := buildStealthPreamble(cfg.PBK, cfg.User, network, destAddr)
	if err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("build XHTTP preamble failed: %w", err)
	}

	bodyStream := io.MultiReader(bytes.NewReader(preamble), pr)
	reqCtx, reqCancel := context.WithCancel(cfg.context())
	req, err := http.NewRequestWithContext(reqCtx, "POST", targetURL, bodyStream)
	if err != nil {
		reqCancel()
		pr.Close()
		pw.Close()
		return nil, err
	}

	// HTTP/2 headers stay inside REALITY; padding only varies the request size.
	req.Host = cfg.SNI
	req.Header.Set("Host", cfg.SNI)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	lazyR := &lazyHTTP2Reader{
		ready: make(chan struct{}),
	}

	go func(usedTr *http2.Transport) {
		defer close(lazyR.ready)
		resp, rtErr := usedTr.RoundTrip(req)
		if rtErr != nil {
			// If transport failed — invalidate only this slot in pool
			xhttpTrMu.Lock()
			for i := range xhttpTransports {
				if xhttpTransports[i] == usedTr {
					xhttpTransports[i] = nil
				}
			}
			xhttpTrMu.Unlock()
			lazyR.err = fmt.Errorf("XHTTP stream RoundTrip failed: %w", rtErr)
			_ = pr.CloseWithError(lazyR.err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lazyR.err = fmt.Errorf("XHTTP stream server returned status: %d %s", resp.StatusCode, resp.Status)
			_ = pr.CloseWithError(lazyR.err)
			return
		}
		lazyR.body = resp.Body
	}(tr)

	remoteAddr, _ := net.ResolveTCPAddr("tcp", cfg.ServerAddr)
	return &http2DuplexConn{
		reader:     lazyR,
		writer:     pw,
		closer:     pw,
		cancel:     reqCancel,
		remoteAddr: remoteAddr,
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080},
		closed:     make(chan struct{}),
	}, nil
}

type http2DuplexConn struct {
	reader        io.ReadCloser
	writer        io.Writer
	closer        io.Closer
	cancel        context.CancelFunc
	remoteAddr    net.Addr
	localAddr     net.Addr
	closeOnce     sync.Once
	closed        chan struct{}
	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
	readWatch     wire.DeadlineWatch
	writeWatch    wire.DeadlineWatch
	writeMu       sync.Mutex
}

func (c *http2DuplexConn) Read(b []byte) (int, error) {
	if dl := c.readDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.readWatch.Begin()
	defer c.readWatch.End()
	n, err := c.reader.Read(b)
	if err != nil {
		if dl := c.readDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, err
}

func (c *http2DuplexConn) Write(b []byte) (int, error) {
	if dl := c.writeDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
		return 0, os.ErrDeadlineExceeded
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writeWatch.Begin()
	defer c.writeWatch.End()

	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	// The HTTP/2 implementation splits DATA at the negotiated frame size.
	// Bound each application write, not each HTTP/2 frame; never wait to fill it.
	const maxFrame = 64 * 1024
	total := 0
	for len(b) > 0 {
		if dl := c.writeDeadline.Load(); dl > 0 && time.Now().UnixNano() >= dl {
			return total, os.ErrDeadlineExceeded
		}
		chunkSize := len(b)
		if chunkSize > maxFrame {
			chunkSize = maxFrame
		}
		n, err := c.writer.Write(b[:chunkSize])
		if n < 0 || n > chunkSize {
			return total, io.ErrShortWrite
		}
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}

func (c *http2DuplexConn) Close() error {
	c.closeOnce.Do(func() {
		c.readWatch.Stop()
		c.writeWatch.Stop()
		close(c.closed)
		if c.cancel != nil {
			c.cancel()
		}
		if c.closer != nil {
			c.closer.Close()
		}
		if c.reader != nil {
			c.reader.Close()
		}
	})
	return nil
}

func (c *http2DuplexConn) CloseWrite() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}

func (c *http2DuplexConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *http2DuplexConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *http2DuplexConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(t.UnixNano())
	}
	c.readWatch.Set(t, func() { _ = c.Close() })
	return nil
}

func (c *http2DuplexConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(t.UnixNano())
	}
	c.writeWatch.Set(t, func() { _ = c.Close() })
	return nil
}

func (c *http2DuplexConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
