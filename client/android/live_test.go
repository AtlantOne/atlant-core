//go:build android || (linux && atlanttest)

package atlant

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type noTCPProtector struct{ denied atomic.Int32 }

func (p *noTCPProtector) Protect(fd int) bool {
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return false
	}
	if kind == syscall.SOCK_STREAM {
		p.denied.Add(1)
		return false
	}
	return true
}

func TestLiveDirectQUICNoTCP(t *testing.T) {
	cfg := liveConfig(t)
	if cfg.WireVersion != 7 {
		t.Skip("wire7 fixture required")
	}
	guard := &noTCPProtector{}
	SetSocketProtector(guard)
	stream, err := dialQUICStream(cfg, "tcp", "speedtest:80")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(stream, "PING direct-no-tcp\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil || line != "PONG direct-no-tcp\n" {
		t.Fatal("invalid direct QUIC reply", line, err)
	}
	if guard.denied.Load() != 0 {
		t.Fatal("direct QUIC attempted a TCP socket")
	}
	t.Log("Android native core: authenticated QUIC stream and PONG with all TCP sockets forbidden; zero TCP attempts")
}

type liveMSSProtector struct{ mss int }

func (p liveMSSProtector) Protect(fd int) bool {
	kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return false
	}
	return kind != syscall.SOCK_STREAM || syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, p.mss) == nil
}

// Explicit opt-in: no credentials or remote addresses are embedded in tests.
func liveConfig(t *testing.T) *Config {
	t.Helper()
	path := os.Getenv("ATLANT_TEST_CONFIG")
	if path == "" {
		t.Skip("set ATLANT_TEST_CONFIG to run live server checks")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Server       string `json:"server"`
		SNI          string `json:"sni"`
		PBK          string `json:"pbk"`
		User         string `json:"user"`
		ServerPubKey string `json:"server_pub_key"`
		WireVersion  int    `json:"wire_version"`
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Server == "" || profile.PBK == "" {
		t.Fatal("incomplete live test profile")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	// The standalone test process is outside VpnService; its sockets already
	// use the physical network and need no Android VPN exclusion.
	SetSocketProtector(testSocketProtector{})
	if value := os.Getenv("ATLANT_TEST_TCP_MSS"); value != "" {
		mss, err := strconv.Atoi(value)
		if err != nil || mss < 536 || mss > 1460 {
			t.Fatal("invalid diagnostic TCP MSS")
		}
		SetSocketProtector(liveMSSProtector{mss: mss})
	}
	if value := os.Getenv("ATLANT_TEST_FINGERPRINT"); value != "" {
		previous := GetFingerprint()
		SetFingerprint(value)
		t.Cleanup(func() { SetFingerprint(previous) })
	}
	t.Cleanup(func() { SetSocketProtector(previous); closeRealitySession(); closeQUICClient("test finished") })
	return &Config{runCtx: ctx, ServerAddr: profile.Server, SNI: profile.SNI, PBK: profile.PBK,
		User: profile.User, ServerPubKey: profile.ServerPubKey, WireVersion: profile.WireVersion, Mux: os.Getenv("ATLANT_TEST_DNS_MUX") == "1"}
}

func checkLiveDNS(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Standard A query for example.com, recursion desired.
	query := []byte{0x41, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeFull(conn, frame); err != nil {
		t.Fatal(err)
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, int(binary.BigEndian.Uint16(header[:])))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if len(response) < 12 || response[0] != query[0] || response[1] != query[1] || response[2]&0x80 == 0 || response[3]&0x0f != 0 || binary.BigEndian.Uint16(response[6:8]) == 0 {
		t.Fatal("server returned an invalid or unsuccessful DNS response")
	}
}

func TestLiveRealityDNS(t *testing.T) {
	cfg := liveConfig(t)
	conn, err := dialRealityTransport(cfg, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	checkLiveDNS(t, conn)
}

func TestLiveRealityDNSConcurrent(t *testing.T) {
	if os.Getenv("ATLANT_TEST_CONCURRENT") != "1" {
		t.Skip("set ATLANT_TEST_CONCURRENT=1 for the bounded concurrency probe")
	}
	cfg := liveConfig(t)
	for i := 0; i < 16; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			conn, err := dialRealityTransport(cfg, "udp", "1.1.1.1:53")
			if err != nil {
				t.Fatal(err)
			}
			checkLiveDNS(t, conn)
		})
	}
}

func TestLiveDNSPooledConcurrent(t *testing.T) {
	if os.Getenv("ATLANT_TEST_CONCURRENT") != "1" {
		t.Skip("set ATLANT_TEST_CONCURRENT=1 for the bounded DNS reuse probe")
	}
	cfg := liveConfig(t)
	for i := 0; i < 16; i++ {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()
			conn, err := dialUDPOverTCP(cfg, "1.1.1.1:53")
			if err != nil {
				t.Fatal(err)
			}
			checkLiveDNS(t, conn)
		})
	}
}

func TestLiveXHTTPDNS(t *testing.T) {
	cfg := liveConfig(t)
	conn, err := dialXHTTPStream(cfg, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	checkLiveDNS(t, conn)
}

func TestLiveQUICHandshake(t *testing.T) {
	cfg := liveConfig(t)
	if _, err := getOrDialQUICClient(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestLiveLegacyVersionsRejected(t *testing.T) {
	version := liveConfig(t).WireVersion
	if version != 4 && version != 7 {
		t.Skip("strict wire4/wire7 deployment only")
	}
	rejected := []int{2, 3}
	if version == 7 {
		rejected = append(rejected, 4, 6)
	}
	for _, version := range rejected {
		cfg := liveConfig(t)
		positive, err := dialRealityConn(cfg)
		if err != nil {
			t.Fatal("current wire positive control failed before legacy probe", err)
		}
		positive.Close()
		legacy := *cfg
		legacy.WireVersion = version
		conn, err := dialRealityConn(&legacy)
		if err == nil {
			conn.Close()
			t.Fatalf("legacy wire%d was accepted by the strict deployment", version)
		}
		t.Logf("legacy wire%d rejected", version)
		positiveCfg := liveConfig(t)
		positive, err = dialRealityConn(positiveCfg)
		if err != nil {
			t.Fatal("current wire positive control failed after legacy probe", err)
		}
		positive.Close()
	}
}

// Opt-in post-deployment verification with actual Android core transports,
// outside Android/JNI. It cannot verify phone routing or video playback.
func TestLiveDNSIPv4Policy(t *testing.T) {
	if os.Getenv("ATLANT_EXPECT_IPV4_DNS") != "1" {
		t.Skip("set ATLANT_EXPECT_IPV4_DNS=1 for the IPv4-policy candidate")
	}
	for _, transport := range []string{"reality", "xhttp", "quic"} {
		for _, network := range []string{"udp", "tcp"} {
			t.Run(transport+"/"+network, func(t *testing.T) {
				cfg := liveConfig(t)
				var conn net.Conn
				var err error
				switch transport {
				case "quic":
					conn, err = dialQUICStream(cfg, network, "1.1.1.1:53")
				case "xhttp":
					conn, err = dialXHTTPStream(cfg, network, "1.1.1.1:53")
				default:
					conn, err = dialRealityTransport(cfg, network, "1.1.1.1:53")
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				stop := context.AfterFunc(cfg.context(), func() { _ = conn.Close() })
				defer stop()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.Type(65)} {
					name, _ := dnsmessage.NewName("www.youtube.com.")
					query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(qtype) + 100, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}}).Pack()
					if err != nil {
						t.Fatal(err)
					}
					frame := make([]byte, 2+len(query))
					binary.BigEndian.PutUint16(frame, uint16(len(query)))
					copy(frame[2:], query)
					if err := writeFull(conn, frame); err != nil {
						t.Fatal(err)
					}
					var prefix [2]byte
					if _, err := io.ReadFull(conn, prefix[:]); err != nil {
						t.Fatal(err)
					}
					packet := make([]byte, int(binary.BigEndian.Uint16(prefix[:])))
					if _, err := io.ReadFull(conn, packet); err != nil {
						t.Fatal(err)
					}
					var response dnsmessage.Message
					if err := response.Unpack(packet); err != nil {
						t.Fatal(err)
					}
					if response.ID != uint16(qtype)+100 || !response.Response || response.RCode != dnsmessage.RCodeSuccess || len(response.Questions) != 1 || response.Questions[0].Type != qtype {
						t.Fatal("invalid DNS reply identity/status")
					}
					if qtype == dnsmessage.TypeA {
						if len(response.Answers) == 0 {
							t.Fatal("A resolution failed")
						}
					} else if len(response.Answers) != 0 || response.AuthenticData {
						t.Fatal("IPv6 discovery policy not applied")
					}
					t.Logf("%s/%s qtype=%d answers=%d", transport, network, qtype, len(response.Answers))
				}
			})
		}
	}
}
