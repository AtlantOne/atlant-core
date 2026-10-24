//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"atlant.local/protocol/settings"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Config struct {
	runCtx           context.Context
	ServerAddr       string
	SNI              string
	PBK              string
	User             string
	TunAddr          string
	TunPrefixLen     int
	TunMTU           int
	ServerPubKey     string // Server static X25519 public key (2-ECDH MitM defense)
	WireVersion      int
	UDPMode          string // UDP obfuscation mode: "chacha20" (default) or "stun"
	Transport        string
	UDPProto         string
	Mux              bool
	FakeDNS          bool
	PaddingEnabled   bool
	MinPadding       int
	MaxPadding       int
	ChaffingEnabled  bool
	ChaffingInterval int
	ChaffingMinBytes int
	ChaffingMaxBytes int
	Fingerprint      string
}

func (c *Config) context() context.Context {
	if c.runCtx != nil {
		return c.runCtx
	}
	return context.Background()
}

const defaultMTU = 1360

type LogListener interface {
	OnLog(msg string, level int64)
}

// TunnelStateListener reports fatal asynchronous TUN failures to Android.
type TunnelStateListener interface {
	OnStateChanged(state string, message string)
}

var (
	lifecycleMu    sync.Mutex
	mu             sync.Mutex
	vpnStack       *stack.Stack
	tunDevice      tun.Device
	cancelFunc     context.CancelFunc
	isRunning      bool
	runWg          sync.WaitGroup
	appLogListener LogListener
	appLogMu       sync.Mutex
	engineLogLevel = "info"
	stateListener  TunnelStateListener
	stateMu        sync.RWMutex
)

// SetLogLevel sets the Android core logging level: debug, info, warn, error, none.
func SetLogLevel(level string) {
	appLogMu.Lock()
	defer appLogMu.Unlock()
	engineLogLevel = strings.ToLower(strings.TrimSpace(level))
}

// SetLogListener registers a Kotlin/Java listener for engine events.
func SetLogListener(l LogListener) {
	appLogMu.Lock()
	appLogListener = l
	appLogMu.Unlock()
}

// SetTunnelStateListener registers a listener for asynchronous tunnel failures.
func SetTunnelStateListener(l TunnelStateListener) {
	stateMu.Lock()
	stateListener = l
	stateMu.Unlock()
}

func reportTunnelFailure(err error) {
	if err == nil {
		return
	}
	stateMu.RLock()
	l := stateListener
	stateMu.RUnlock()
	if l != nil {
		l.OnStateChanged("failed", err.Error())
	}
}

// NotifyNetworkChanged drops pooled transports so new flows bind to the new
// Android underlying network through VpnService.protect().
func NotifyNetworkChanged() {
	setUDPBlocked(false)
	closeRealitySession()
	closeQUICClient("underlying network changed")
	closeXHTTPTransport()
}

var (
	optMu               sync.RWMutex
	optTunMTU           int    = defaultMTU
	optFakeDNS          bool   = true
	optPadding          bool   = true
	optAutoFallback     bool   = true
	optPortHopping      bool   = false
	optRemoteDNS        bool   = true
	optDecoyTraffic     bool   = false
	optZeroRTT          bool   = true
	optFingerprint      string = "firefox"
	optMinPadding       int    = 32
	optMaxPadding       int    = 256
	optChaffingEnabled  bool   = true
	optChaffingInterval int    = 10
	optMux              bool   = false
	optWireVersion      int    = 6
)

// SetWireVersion selects the explicit client/server protocol format.
func SetWireVersion(version int) error {
	if version != 2 && version != 3 && version != 4 && version != 6 && version != 7 {
		return fmt.Errorf("unsupported wire version")
	}
	optMu.Lock()
	optWireVersion = version
	optMu.Unlock()
	return nil
}

// SetTunMTU keeps the Go stack aligned with the Android TUN interface.
func SetTunMTU(mtu int) {
	if mtu < 1200 {
		mtu = 1200
	}
	if mtu > 1500 {
		mtu = 1500
	}
	optMu.Lock()
	optTunMTU = mtu
	optMu.Unlock()
}

// SetMuxEnabled configures multiplexing mode (true = Yamux mux, false = direct 1-to-1).
func SetMuxEnabled(enabled bool) {
	optMu.Lock()
	optMux = enabled
	optMu.Unlock()
}

func IsMuxEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optMux
}

// SetFingerprint sets the uTLS fingerprint profile ("chrome", "firefox", "safari", "ios", "edge", "randomized").
func SetFingerprint(fp string) {
	optMu.Lock()
	p := strings.ToLower(strings.TrimSpace(fp))
	if p == "" {
		p = "firefox"
	}
	optFingerprint = p
	optMu.Unlock()
}

func GetFingerprint() string {
	optMu.RLock()
	defer optMu.RUnlock()
	return optFingerprint
}

// SetPaddingRange configures minimum and maximum packet padding bounds in bytes.
func SetPaddingRange(minPad, maxPad int) {
	optMu.Lock()
	optMinPadding, optMaxPadding = settings.PaddingRange(minPad, maxPad)
	optMu.Unlock()
}

// SetChaffing toggles background heartbeat micro-noise and pulse interval.
func SetChaffing(enabled bool, intervalSec int) {
	optMu.Lock()
	optChaffingEnabled = enabled
	if intervalSec > 0 {
		optChaffingInterval = intervalSec
	}
	optMu.Unlock()
}

func IsChaffingEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optChaffingEnabled
}

// SetFakeDnsEnabled configures 0ms synthetic DNS resolver pool (198.18.0.0/15).
func SetFakeDnsEnabled(enabled bool) {
	optMu.Lock()
	optFakeDNS = enabled
	optMu.Unlock()
}

func IsFakeDnsEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optFakeDNS
}

// SetTrafficPadding toggles dynamic packet length padding against ML DPI models.
func SetTrafficPadding(enabled bool) {
	optMu.Lock()
	optPadding = enabled
	optMu.Unlock()
}

func IsTrafficPaddingEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optPadding
}

// SetAutoFallback toggles Happy Eyeballs v2 seamless QUIC <-> TCP handover.
func SetAutoFallback(enabled bool) {
	optMu.Lock()
	optAutoFallback = enabled
	optMu.Unlock()
}

func IsAutoFallbackEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optAutoFallback
}

// SetPortHopping toggles dynamic UDP port rotation upon TSPU throttling.
func SetPortHopping(enabled bool) {
	optMu.Lock()
	optPortHopping = enabled
	optMu.Unlock()
}

func IsPortHoppingEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optPortHopping
}

// SetRemoteDns configures encrypted DNS streaming to the server.
func SetRemoteDns(enabled bool) {
	optMu.Lock()
	optRemoteDNS = enabled
	optMu.Unlock()
}

func IsRemoteDnsEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optRemoteDNS
}

// SetDecoyTraffic enables realistic background decoy HTTP requests.
func SetDecoyTraffic(enabled bool) {
	optMu.Lock()
	optDecoyTraffic = enabled
	optMu.Unlock()
}

func IsDecoyTrafficEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optDecoyTraffic
}

// SetZeroRtt enables 0-RTT session resumption tokens.
func SetZeroRtt(enabled bool) {
	optMu.Lock()
	optZeroRTT = enabled
	optMu.Unlock()
}

func IsZeroRttEnabled() bool {
	optMu.RLock()
	defer optMu.RUnlock()
	return optZeroRTT
}

type engineLogWriter struct{}

func (w *engineLogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		appLogMu.Lock()
		lvlSetting := engineLogLevel
		l := appLogListener
		appLogMu.Unlock()

		lower := strings.ToLower(msg)
		isError := strings.Contains(msg, "[ERR") || strings.Contains(lower, "error") || strings.Contains(lower, "failed")
		isWarn := strings.Contains(msg, "[WARN") || strings.Contains(lower, "warn") || strings.Contains(lower, "timeout")
		isDebug := strings.Contains(msg, "[DEBUG") || strings.Contains(lower, "debug") || strings.Contains(msg, "[AUTH-DEBUG") || strings.Contains(msg, "[QUIC-AUTH-DEBUG")

		var lvl int64 = 0 // 0 = INFO, 1 = SUCCESS, 2 = WARN, 3 = ERROR
		if isError {
			lvl = 3
		} else if isWarn {
			lvl = 2
		} else if strings.Contains(lower, "connected") || strings.Contains(lower, "started") || strings.Contains(lower, "success") {
			lvl = 1
		}

		allow := false
		switch lvlSetting {
		case "none", "silent", "off":
			// Never hide fatal engine failures.  They are required to diagnose
			// device-specific TUN initialization errors.
			allow = isError
		case "error":
			allow = isError
		case "warn", "warning":
			allow = isError || isWarn
		case "info":
			allow = !isDebug
		case "debug":
			allow = true
		default:
			allow = !isDebug
		}

		if allow && l != nil {
			l.OnLog(msg, lvl)
		}
	}
	return os.Stderr.Write(p)
}

func init() {
	log.SetFlags(0)
	log.SetOutput(&engineLogWriter{})
}

func main() {}

// StartVPN starts the VPN tunnel without username authorization.
func StartVPN(server, sni, pbk, tunAddr string, tunFd int, tunPrefixLen int) error {
	return StartVPNWithUser(server, sni, pbk, "", "", "chacha20", tunAddr, tunFd, tunPrefixLen)
}

// StartVPNWithUser starts the VPN tunnel with user authorization via Reality SessionID.
func StartVPNWithUser(server, sni, pbk, user, serverPubKey, udpMode, tunAddr string, tunFd int, tunPrefixLen int) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	mu.Lock()
	if isRunning {
		mu.Unlock()
		return fmt.Errorf("VPN is already running")
	}
	setUDPBlocked(false)
	if udpMode == "" {
		udpMode = "chacha20"
	}
	optMu.RLock()
	minPadding, maxPadding, chaffingInterval := optMinPadding, optMaxPadding, optChaffingInterval
	tunMTU := optTunMTU
	wireVersion := optWireVersion
	optMu.RUnlock()
	cfg := &Config{
		ServerAddr:       server,
		SNI:              sni,
		PBK:              pbk,
		User:             user,
		ServerPubKey:     serverPubKey,
		WireVersion:      wireVersion,
		UDPMode:          udpMode,
		Transport:        GetTCPProto(),
		UDPProto:         "quic",
		Mux:              IsMuxEnabled(),
		FakeDNS:          IsFakeDnsEnabled(),
		TunAddr:          tunAddr,
		TunPrefixLen:     tunPrefixLen,
		TunMTU:           tunMTU,
		PaddingEnabled:   IsTrafficPaddingEnabled(),
		MinPadding:       minPadding,
		MaxPadding:       maxPadding,
		ChaffingEnabled:  IsChaffingEnabled(),
		ChaffingInterval: chaffingInterval,
		ChaffingMinBytes: 64,
		ChaffingMaxBytes: 512,
		Fingerprint:      GetFingerprint(),
	}
	var ctx context.Context
	ctx, cancelFunc = context.WithCancel(context.Background())
	cfg.runCtx = ctx
	sessionCancel := cancelFunc
	isRunning = true
	mu.Unlock()

	runWg.Add(1)
	ready := make(chan error, 1)
	go func() {
		defer runWg.Done()
		defer sessionCancel()
		defer func() {
			if recovered := recover(); recovered != nil {
				select {
				case ready <- fmt.Errorf("panic while starting Android TUN: %v", recovered):
				default:
				}
			}
		}()
		startTun(ctx, cfg, tunFd, ready)
	}()
	if err := <-ready; err != nil {
		sessionCancel()
		runWg.Wait()
		mu.Lock()
		isRunning = false
		cancelFunc = nil
		mu.Unlock()
		return fmt.Errorf("initialize Android TUN: %w", err)
	}
	go startChaffingWorker(ctx, cfg)
	if IsDecoyTrafficEnabled() {
		startDecoyTrafficGenerator(cfg)
	}
	return nil
}

// StopVPN gracefully stops the VPN session and releases resources.
func StopVPN() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	mu.Lock()
	if !isRunning {
		mu.Unlock()
		return
	}
	if cancelFunc != nil {
		cancelFunc()
	}
	if tunDevice != nil {
		_ = tunDevice.Close()
	}
	sessMu.Lock()
	if session != nil {
		_ = session.Close()
		session = nil
	}
	sessMu.Unlock()
	closeXHTTPTransport()
	closeQUICClient("VPN stopped")
	mu.Unlock()
	runWg.Wait()
	mu.Lock()
	isRunning = false
	setUDPBlocked(false)
	mu.Unlock()
}
