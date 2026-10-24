package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var configMu sync.RWMutex

type RuntimeConfig struct {
	SNI, AdvertiseAddr string
	UpMbps, DownMbps   uint64
	DNSIPv4Only        bool
}

func (c *Config) Runtime() RuntimeConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	up, down := c.UpMbps, c.DownMbps
	if c.Bandwidth.UpMbps > 0 {
		up = c.Bandwidth.UpMbps
	}
	if c.Bandwidth.DownMbps > 0 {
		down = c.Bandwidth.DownMbps
	}
	return RuntimeConfig{SNI: c.SNI, AdvertiseAddr: c.AdvertiseAddr, UpMbps: up, DownMbps: down, DNSIPv4Only: c.DNSIPv4Only}
}

func (c *Config) GetSNI() string { configMu.RLock(); defer configMu.RUnlock(); return c.SNI }
func (c *Config) GetAdvertiseAddr() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return c.AdvertiseAddr
}

// BandwidthConfig holds upload and download rate limits in Mbps (0 = unlimited / maximum line speed).
type BandwidthConfig struct {
	UpMbps   uint64 `json:"up_mbps"`
	DownMbps uint64 `json:"down_mbps"`
}

// QuicConfig holds performance and socket buffer tuning options for QUIC/Hysteria.
type QuicConfig struct {
	MaxIdleTimeoutSec     int  `json:"max_idle_timeout_sec"`     // Default: 30s
	KeepAlivePeriodSec    int  `json:"keep_alive_period_sec"`    // Default: 10s
	StreamReceiveWindowMB int  `json:"stream_receive_window_mb"` // Maximum; zero selects 32 MiB.
	ConnReceiveWindowMB   int  `json:"conn_receive_window_mb"`   // Maximum; zero selects 64 MiB.
	SocketBufferSizeMB    int  `json:"socket_buffer_size_mb"`    // Default: 8 (8MB)
	DisablePacer          bool `json:"disable_pacer"`            // If true, pacer is disabled completely
}

// YamuxConfig holds multiplexing window and timeout options for Reality TCP tunnels.
type YamuxConfig struct {
	MaxStreamWindowKB     int `json:"max_stream_window_kb"`     // Default: 1024 (1MB)
	MaxConnectionWindowKB int `json:"max_connection_window_kb"` // Default: 4096 (4MB)
	KeepAlivePeriodSec    int `json:"keep_alive_period_sec"`    // Default: 25s
	WriteTimeoutSec       int `json:"write_timeout_sec"`        // Default: 15s
}

// Config represents full server configuration, supporting JSON config files, URLs, and CLI flags.
type Config struct {
	InboundID     string             `json:"-"`
	ConfigFile    string             `json:"-"`
	ServerAddr    string             `json:"listen"`                 // Listen address, e.g. ":443" or "0.0.0.0:443"
	ServerPath    string             `json:"path"`                   // XHTTP path, default "/api/v1/sync"
	SNI           string             `json:"sni"`                    // SNI donor domain, e.g. "www.microsoft.com"
	UsersFile     string             `json:"users_file"`             // SQLite path; legacy .json is imported once into adjacent .db.
	AdvertiseAddr string             `json:"advertise_addr"`         // Public IP:port advertised to clients
	LocalPort     string             `json:"local_port"`             // Default :1080
	Transport     string             `json:"transport"`              // "auto", "reality", "xhttp"
	Path          string             `json:"xhttp_path"`             // Alternative path mapping
	Mode          string             `json:"mode"`                   // "stream" or "packet-up"
	CertFile      string             `json:"cert_file"`              // Genuine TLS certificate (optional)
	KeyFile       string             `json:"key_file"`               // Genuine TLS private key (optional)
	ServerKeyFile string             `json:"server_key_file"`        // Reality 2-ECDH static X25519 private key file
	Debug         bool               `json:"debug"`                  // Verbose debug logging (legacy flag)
	LogLevel      string             `json:"log_level"`              // "debug", "info", "warn", "error", "none"
	APIAddr       string             `json:"api_addr"`               // Management REST API listen address (default: "127.0.0.1:8080")
	APISecret     string             `json:"api_secret"`             // Optional bearer secret token for API access
	DNSIPv4Only   bool               `json:"dns_ipv4_only"`          // Opt-in DNS discovery policy for hosts without IPv6 egress.
	WireVersion   int                `json:"wire_version,omitempty"` // 6: ticketless full-ClientHello admission.
	LegacyWire    bool               `json:"legacy_wire"`            // Explicit coexistence; new clients never downgrade themselves.
	Subscriptions SubscriptionConfig `json:"subscriptions"`
	Quota         QuotaConfig        `json:"quota"`

	// Bandwidth rate limits (0 = unlimited / line speed)
	UpMbps    uint64          `json:"up_mbps"`
	DownMbps  uint64          `json:"down_mbps"`
	Bandwidth BandwidthConfig `json:"bandwidth"`

	// Sub-system tuning
	Quic  QuicConfig  `json:"quic"`
	Yamux YamuxConfig `json:"yamux"`
}

// DefaultConfig returns server configuration populated with production defaults.
func DefaultConfig() *Config {
	return &Config{
		ServerAddr:    ":443",
		ServerPath:    "/api/v1/sync",
		Path:          "/api/v1/sync",
		SNI:           "www.microsoft.com",
		UsersFile:     "users.db",
		LocalPort:     ":1080",
		Transport:     "auto",
		Mode:          "stream",
		ServerKeyFile: "atlant_server_key.bin",
		WireVersion:   6,
		LegacyWire:    false,
		LogLevel:      "error",
		APIAddr:       "127.0.0.1:8080",
		APISecret:     "",
		UpMbps:        0, // 0 = unlimited
		DownMbps:      0, // 0 = unlimited
		Quic: QuicConfig{
			MaxIdleTimeoutSec:     30,
			KeepAlivePeriodSec:    10,
			StreamReceiveWindowMB: 32,
			ConnReceiveWindowMB:   64,
			SocketBufferSizeMB:    8,
			DisablePacer:          false,
		},
		Yamux: YamuxConfig{
			MaxStreamWindowKB:     16384, // 16MB window for unthrottled gigabit speed
			MaxConnectionWindowKB: 32768, // 32MB connection window
			KeepAlivePeriodSec:    25,
			WriteTimeoutSec:       30,
		},
	}
}

// GetUpMbps returns effective upload limit in Mbps (0 = unlimited).
func (c *Config) GetUpMbps() uint64 {
	configMu.RLock()
	defer configMu.RUnlock()
	if c.Bandwidth.UpMbps > 0 {
		return c.Bandwidth.UpMbps
	}
	return c.UpMbps
}

// GetDownMbps returns effective download limit in Mbps (0 = unlimited).
func (c *Config) GetDownMbps() uint64 {
	configMu.RLock()
	defer configMu.RUnlock()
	if c.Bandwidth.DownMbps > 0 {
		return c.Bandwidth.DownMbps
	}
	return c.DownMbps
}

// GetQuicSocketBufferSize returns buffer size in bytes for UDP sockets.
func (c *Config) GetQuicSocketBufferSize() int {
	mb := c.Quic.SocketBufferSizeMB
	if mb <= 0 {
		mb = 8
	}
	return mb * 1024 * 1024
}

// GetQuicStreamReceiveWindow returns stream receive window in bytes.
func (c *Config) GetQuicStreamReceiveWindow() uint64 {
	mb := c.Quic.StreamReceiveWindowMB
	if mb <= 0 {
		mb = 32
	}
	return uint64(mb) * 1024 * 1024
}

// GetQuicConnReceiveWindow returns connection receive window in bytes.
func (c *Config) GetQuicConnReceiveWindow() uint64 {
	mb := c.Quic.ConnReceiveWindowMB
	if mb <= 0 {
		mb = 64
	}
	return uint64(mb) * 1024 * 1024
}

// GetQuicMaxIdleTimeout returns QUIC idle timeout duration.
func (c *Config) GetQuicMaxIdleTimeout() time.Duration {
	sec := c.Quic.MaxIdleTimeoutSec
	if sec <= 0 {
		sec = 30
	}
	return time.Duration(sec) * time.Second
}

// GetQuicKeepAlivePeriod returns QUIC keep-alive period duration.
func (c *Config) GetQuicKeepAlivePeriod() time.Duration {
	sec := c.Quic.KeepAlivePeriodSec
	if sec <= 0 {
		sec = 10
	}
	return time.Duration(sec) * time.Second
}

// GetYamuxStreamWindow returns Yamux stream window in bytes.
func (c *Config) GetYamuxStreamWindow() uint32 {
	kb := c.Yamux.MaxStreamWindowKB
	if kb <= 0 {
		kb = 16384
	}
	return uint32(kb) * 1024
}

// GetYamuxConnWindow returns Yamux connection window in bytes.
func (c *Config) GetYamuxConnWindow() uint32 {
	kb := c.Yamux.MaxConnectionWindowKB
	if kb <= 0 {
		kb = 32768
	}
	return uint32(kb) * 1024
}

// LoadConfigFromFile loads and parses a JSON config file into Config.
func LoadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file %s: %w", path, err)
	}

	conf := DefaultConfig()
	if err := json.Unmarshal(data, conf); err != nil {
		return nil, fmt.Errorf("parse json config %s: %w", path, err)
	}
	conf.ConfigFile = path

	if conf.Path != "" && conf.ServerPath == "" {
		conf.ServerPath = conf.Path
	}
	if conf.ServerPath != "" && conf.Path == "" {
		conf.Path = conf.ServerPath
	}
	return conf, nil
}

// ParseAtlantURL parses an atlant:// URL into Config.
func ParseAtlantURL(configStr string) (*Config, error) {
	u, err := url.Parse(configStr)
	if err != nil {
		return nil, err
	}
	conf := DefaultConfig()
	conf.ServerAddr = u.Host
	conf.ServerPath = u.Path
	q := u.Query()
	if sni := q.Get("sni"); sni != "" {
		conf.SNI = sni
	}
	if usersFile := q.Get("users"); usersFile != "" {
		conf.UsersFile = usersFile
	}
	if pub := q.Get("pub"); pub != "" {
		conf.AdvertiseAddr = pub
	} else if public := q.Get("public"); public != "" {
		conf.AdvertiseAddr = public
	}
	return conf, nil
}

// FindConfigFile looks for config.json in working directory or next to executable.
func FindConfigFile(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}
	for _, candidate := range []string{"config.json", "server_config.json"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, candidate := range []string{"config.json", "server_config.json"} {
			p := filepath.Join(dir, candidate)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}
