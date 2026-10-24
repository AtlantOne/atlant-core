package main

import (
	"atlant.local/protocol/settings"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hashicorp/yamux"
	"golang.org/x/sys/windows"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
)

type Config struct {
	ServerAddr       string   `json:"server"`
	BackupServers    []string `json:"backup_servers"`
	SNI              string   `json:"sni"`
	PBK              string   `json:"pbk"`
	User             string   `json:"user"`
	LocalPort        string   `json:"local"`
	Tun              bool     `json:"tun"`
	TunName          string   `json:"tun_name"`
	TunAddr          string   `json:"tun_addr"`
	TunGw            string   `json:"tun_gw"`
	TunMask          string   `json:"tun_mask"`
	TunDNS           string   `json:"tun_dns"`
	KillSwitch       bool     `json:"kill_switch"`
	Transport        string   `json:"transport"`
	Path             string   `json:"path"`
	Mode             string   `json:"mode"`
	ContentType      string   `json:"content_type"`
	TrafficMode      string   `json:"traffic_mode"`   // "split", "tcp", "udp"
	UDPProto         string   `json:"udp_proto"`      // "quic", "tcp"
	TCPProto         string   `json:"tcp_proto"`      // "reality", "xhttp"
	RouteMode        string   `json:"route_mode"`     // "all", "proxy_apps", "bypass_apps"
	ProxyApps        []string `json:"proxy_apps"`     // Executables to proxy when RouteMode == "proxy_apps"
	BypassApps       []string `json:"bypass_apps"`    // Executables to bypass when RouteMode == "bypass_apps"
	ProxyDomains     []string `json:"proxy_domains"`  // Domains to proxy (legacy fallback)
	DirectDomains    []string `json:"direct_domains"` // Domains to bypass (legacy fallback)
	ServerPubKey     string   `json:"server_pub_key"` // Static X25519 public key for 2-ECDH MitM defense
	WireVersion      int      `json:"wire_version,omitempty"`
	UDPMode          string   `json:"udp_mode"`           // Alias/fallback for UDP protocol mode
	UpMbps           uint64   `json:"up_mbps"`            // Upload limit in Mbps (0 = unlimited)
	DownMbps         uint64   `json:"down_mbps"`          // Download limit in Mbps (0 = unlimited)
	MTU              int      `json:"mtu"`                // Maximum Transmission Unit (default 1420)
	AllowLAN         bool     `json:"allow_lan"`          // Allow SOCKS5 from local network
	BlockIPv6        bool     `json:"block_ipv6"`         // Block IPv6 to prevent leaks
	Mux              bool     `json:"mux"`                // Enable Yamux stream multiplexing (default false = direct 1-to-1)
	LogLevel         string   `json:"log_level"`          // "debug", "info", "warn", "error", "none"
	FakeDNS          bool     `json:"fake_dns"`           // Synthetic 0ms DNS resolver pool (198.18.0.0/15)
	TrafficPadding   bool     `json:"traffic_padding"`    // Random packet length padding against ML DPI models
	AutoFallback     bool     `json:"auto_fallback"`      // Happy Eyeballs v2 seamless QUIC <-> TCP handover
	PortHopping      bool     `json:"port_hopping"`       // Dynamic UDP port rotation upon TSPU throttling
	RemoteDNS        bool     `json:"remote_dns"`         // Encrypted remote DNS tunnel stream
	DecoyTraffic     bool     `json:"decoy_traffic"`      // Periodic realistic background decoy requests
	ZeroRTT          bool     `json:"zero_rtt"`           // 0-RTT session resumption tokens
	Fingerprint      string   `json:"fingerprint"`        // uTLS profile: "chrome", "firefox", "safari", "ios", "edge", "randomized"
	PaddingEnabled   bool     `json:"padding_enabled"`    // Random frame padding against ML-based DPI
	MinPadding       int      `json:"min_padding"`        // Minimum padding bytes (e.g. 16..64)
	MaxPadding       int      `json:"max_padding"`        // Maximum padding bytes (e.g. 64..512)
	ChaffingEnabled  bool     `json:"chaffing_enabled"`   // Background heartbeat micro-noise
	ChaffingInterval int      `json:"chaffing_interval"`  // Seconds between chaffing pulses
	ChaffingMinBytes int      `json:"chaffing_min_bytes"` // Minimum chaffing bytes
	ChaffingMaxBytes int      `json:"chaffing_max_bytes"` // Maximum chaffing bytes
}

func parseConfig() *Config {
	cfg := &Config{
		WireVersion:      6,
		ServerAddr:       "127.0.0.1:443",
		LocalPort:        "127.0.0.1:1080",
		TunName:          "AtlantVPN",
		TunAddr:          "10.254.1.2",
		TunGw:            "10.254.1.1",
		TunMask:          "255.255.255.0",
		TunDNS:           "1.1.1.1",
		TrafficMode:      "split",
		RouteMode:        "all",
		FakeDNS:          true,
		TrafficPadding:   true,
		AutoFallback:     true,
		PortHopping:      false,
		RemoteDNS:        true,
		DecoyTraffic:     false,
		ZeroRTT:          true,
		Fingerprint:      "firefox",
		PaddingEnabled:   true,
		MinPadding:       32,
		MaxPadding:       256,
		ChaffingEnabled:  true,
		ChaffingInterval: 10,
		ChaffingMinBytes: 16,
		ChaffingMaxBytes: 64,
	}

	// Try to load from config file first
	configFile := "atlant_config.json"
	if _, err := os.Stat(configFile); err != nil {
		if exe, err := os.Executable(); err == nil {
			exeConfig := filepath.Join(filepath.Dir(exe), "atlant_config.json")
			if _, err := os.Stat(exeConfig); err == nil {
				configFile = exeConfig
			}
		}
	}
	if _, err := os.Stat(configFile); err == nil && !skipAutomaticConfig(os.Args[1:]) {
		if fileCfg := loadConfigFromFile(configFile); fileCfg != nil {
			cfg = fileCfg
		}
	}

	server := flag.String("server", "", "Reality server address")
	flag.Bool("no-config", false, "Use explicit launch parameters, do not load an automatic config file")
	backupServersFlag := flag.String("backup-servers", "", "Comma-separated backup server addresses")
	sni := flag.String("sni", "", "SNI for TLS handshake (e.g. vk.com)")
	pbk := flag.String("pbk", "", "Reality PBK (pre-shared key, required)")
	pbkStdin := flag.Bool("pbk-stdin", false, "Read PBK from inherited stdin, never process arguments")
	user := flag.String("user", "", "Username (optional) for users.json auth")
	local := flag.String("local", "", "Local SOCKS5 listen port")
	useTun := flag.Bool("tun", false, "Enable TUN mode (requires Admin and wintun.dll)")
	tunName := flag.String("tun-name", "", "TUN interface name")
	tunAddr := flag.String("tun-addr", "", "TUN interface IP")
	tunGw := flag.String("tun-gw", "", "TUN gateway IP")
	tunMask := flag.String("tun-mask", "", "TUN netmask")
	tunDNS := flag.String("tun-dns", "", "DNS server for TUN")
	killSwitch := flag.Bool("kill-switch", false, "Enable Kill Switch (block internet if VPN drops)")
	transport := flag.String("transport", "", "Transport protocol: reality or xhttp")
	path := flag.String("path", "", "XHTTP URL path endpoint (e.g. /api/v1/sync)")
	mode := flag.String("mode", "", "XHTTP mode: stream or packet-up")
	contentType := flag.String("content-type", "", "XHTTP Content-Type")
	trafficMode := flag.String("traffic-mode", "", "Traffic mode: split, tcp, or udp")
	udpProto := flag.String("udp-proto", "", "UDP transport protocol: quic or tcp")
	udpModeFlag := flag.String("udp-mode", "", "UDP mode alias: quic or tcp")
	tcpProto := flag.String("tcp-proto", "", "TCP transport protocol: reality or xhttp")
	routeMode := flag.String("route-mode", "", "Route mode: all, rules, or bypass")
	serverPubKey := flag.String("server-pub-key", "", "Static X25519 public key for Reality 2-ECDH")
	wireVersion := flag.Int("wire-version", 0, "Explicit wire format 2, 3, 4, 6 or 7; never auto-downgrade")
	mtu := flag.Int("mtu", 1360, "TUN MTU (1280-1500)")
	allowLAN := flag.Bool("allow-lan", false, "Allow SOCKS5 proxy from local network")
	blockIPv6 := flag.Bool("block-ipv6", false, "Block IPv6 to prevent leaks")
	upMbps := flag.Uint64("up-mbps", 0, "Upload limit in Mbps")
	downMbps := flag.Uint64("down-mbps", 0, "Download limit in Mbps")
	proxyAppsFlag := flag.String("proxy-apps", "", "Comma-separated executable names to proxy")
	bypassAppsFlag := flag.String("bypass-apps", "", "Comma-separated executable names to bypass")
	proxyDomainsFlag := flag.String("proxy-domains", "", "Comma-separated domains/CIDRs to proxy")
	directDomainsFlag := flag.String("direct-domains", "", "Comma-separated domains/CIDRs to bypass")
	muxFlag := flag.Bool("mux", false, "Enable Yamux stream multiplexing (default false = direct 1-to-1)")
	fakeDNSFlag := flag.Bool("fake-dns", true, "Synthetic 0ms DNS resolver pool")
	autoFallbackFlag := flag.Bool("auto-fallback", true, "QUIC to TCP auto-fallback")
	remoteDNSFlag := flag.Bool("remote-dns", true, "Encrypted remote DNS tunnel stream")
	logLevelFlag := flag.String("loglevel", "", "Log level: debug, info, warn, error, none")
	fingerprintFlag := flag.String("fingerprint", "", "uTLS ClientHello fingerprint profile: chrome, firefox, safari, ios, edge, randomized")
	paddingEnabledFlag := flag.Bool("padding", true, "Enable random frame padding")
	minPaddingFlag := flag.Int("min-padding", 0, "Minimum padding bytes")
	maxPaddingFlag := flag.Int("max-padding", 0, "Maximum padding bytes")
	chaffingEnabledFlag := flag.Bool("chaffing", true, "Enable background chaffing micro-noise")
	chaffingIntervalFlag := flag.Int("chaffing-interval", 0, "Chaffing interval in seconds")
	chaffingMinBytesFlag := flag.Int("chaffing-min-bytes", 0, "Minimum chaffing bytes")
	chaffingMaxBytesFlag := flag.Int("chaffing-max-bytes", 0, "Maximum chaffing bytes")

	flag.Parse()
	if *wireVersion != 0 {
		cfg.WireVersion = *wireVersion
	}

	if *fingerprintFlag != "" {
		cfg.Fingerprint = *fingerprintFlag
	}
	if *minPaddingFlag > 0 {
		cfg.MinPadding = *minPaddingFlag
	}
	if *maxPaddingFlag > 0 {
		cfg.MaxPadding = *maxPaddingFlag
	}
	if *chaffingIntervalFlag > 0 {
		cfg.ChaffingInterval = *chaffingIntervalFlag
	}
	if *chaffingMinBytesFlag > 0 {
		cfg.ChaffingMinBytes = *chaffingMinBytesFlag
	}
	if *chaffingMaxBytesFlag > 0 {
		cfg.ChaffingMaxBytes = *chaffingMaxBytesFlag
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "padding":
			cfg.PaddingEnabled = *paddingEnabledFlag
		case "chaffing":
			cfg.ChaffingEnabled = *chaffingEnabledFlag
		case "mtu":
			if *mtu > 0 {
				cfg.MTU = *mtu
			}
		case "tun":
			cfg.Tun = *useTun
		case "kill-switch":
			cfg.KillSwitch = *killSwitch
		case "allow-lan":
			cfg.AllowLAN = *allowLAN
		case "block-ipv6":
			cfg.BlockIPv6 = *blockIPv6
		case "mux":
			cfg.Mux = *muxFlag
		case "fake-dns":
			cfg.FakeDNS = *fakeDNSFlag
		case "auto-fallback":
			cfg.AutoFallback = *autoFallbackFlag
		case "remote-dns":
			cfg.RemoteDNS = *remoteDNSFlag
		}
	})

	if *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	if *upMbps > 0 {
		cfg.UpMbps = *upMbps
	}
	if *downMbps > 0 {
		cfg.DownMbps = *downMbps
	}
	if *proxyAppsFlag != "" {
		cfg.ProxyApps = nil
		for _, p := range strings.Split(*proxyAppsFlag, ",") {
			if s := strings.TrimSpace(p); s != "" {
				cfg.ProxyApps = append(cfg.ProxyApps, s)
			}
		}
	}
	if *bypassAppsFlag != "" {
		cfg.BypassApps = nil
		for _, p := range strings.Split(*bypassAppsFlag, ",") {
			if s := strings.TrimSpace(p); s != "" {
				cfg.BypassApps = append(cfg.BypassApps, s)
			}
		}
	}
	if *proxyDomainsFlag != "" {
		cfg.ProxyDomains = nil
		for _, p := range strings.Split(*proxyDomainsFlag, ",") {
			if s := strings.TrimSpace(p); s != "" {
				cfg.ProxyDomains = append(cfg.ProxyDomains, s)
			}
		}
	}
	if *directDomainsFlag != "" {
		cfg.DirectDomains = nil
		for _, p := range strings.Split(*directDomainsFlag, ",") {
			if s := strings.TrimSpace(p); s != "" {
				cfg.DirectDomains = append(cfg.DirectDomains, s)
			}
		}
	}

	if *server != "" {
		cfg.ServerAddr = *server
	}
	if *backupServersFlag != "" {
		cfg.BackupServers = nil
		for _, b := range strings.Split(*backupServersFlag, ",") {
			if s := strings.TrimSpace(b); s != "" {
				cfg.BackupServers = append(cfg.BackupServers, s)
			}
		}
	}
	if *udpModeFlag != "" {
		cfg.UDPMode = *udpModeFlag
		cfg.UDPProto = *udpModeFlag
	}
	if *sni != "" {
		cfg.SNI = *sni
	}
	if *pbk != "" {
		cfg.PBK = *pbk
	}
	if *user != "" {
		cfg.User = strings.TrimSpace(*user)
	}
	if *serverPubKey != "" {
		cfg.ServerPubKey = strings.TrimSpace(*serverPubKey)
	}
	if *local != "" {
		cfg.LocalPort = *local
	}
	cfg.MinPadding, cfg.MaxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	cfg.ChaffingMinBytes, cfg.ChaffingMaxBytes = settings.PaddingRange(cfg.ChaffingMinBytes, cfg.ChaffingMaxBytes)
	if *tunName != "" {
		cfg.TunName = *tunName
	}
	if *tunAddr != "" {
		cfg.TunAddr = *tunAddr
	}
	if *tunGw != "" {
		cfg.TunGw = *tunGw
	}
	if *tunMask != "" {
		cfg.TunMask = *tunMask
	}
	if *tunDNS != "" {
		cfg.TunDNS = *tunDNS
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if cfg.Transport == "" {
		cfg.Transport = "reality"
	}
	if *path != "" {
		cfg.Path = *path
	}
	if cfg.Path == "" {
		cfg.Path = "/api/v1/sync"
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if cfg.Mode == "" {
		cfg.Mode = "stream"
	}
	if *contentType != "" {
		cfg.ContentType = *contentType
	}
	if cfg.ContentType == "" {
		cfg.ContentType = "application/octet-stream"
	}
	if *trafficMode != "" {
		cfg.TrafficMode = *trafficMode
	}
	if cfg.TrafficMode == "" {
		cfg.TrafficMode = "split"
	}
	if *udpProto != "" {
		cfg.UDPProto = *udpProto
	}
	if *tcpProto != "" {
		cfg.TCPProto = *tcpProto
	}
	if strings.ToLower(cfg.Transport) == "xhttp" || strings.ToLower(cfg.TCPProto) == "xhttp" {
		cfg.Transport = "xhttp"
		cfg.TCPProto = "xhttp"
	}
	if cfg.TCPProto == "" {
		cfg.TCPProto = "reality"
	}
	if *routeMode != "" {
		cfg.RouteMode = *routeMode
	}
	if cfg.RouteMode == "" {
		cfg.RouteMode = "all"
	}

	// Warn when the profile does not pin the server's static key.
	if cfg.ServerPubKey == "" {
		log.Printf("[CONFIG] Missing server_pub_key. If the server requires 2-ECDH, provide its public key in the profile or configuration.")
	}

	if cfg.SNI == "" {
		fmt.Println("Usage: atlant_win -server 1.2.3.4:443 -sni vk.com -pbk <key> [-local 127.0.0.1:1080]")
		os.Exit(1)
	}

	if *pbkStdin {
		if *pbk != "" {
			fmt.Println("Choose either -pbk or -pbk-stdin")
			os.Exit(1)
		}
		key, err := readPBKFromPipe(os.Stdin)
		if err != nil {
			fmt.Println("Cannot read private PBK input")
			os.Exit(1)
		}
		cfg.PBK = key
	}
	if cfg.PBK == "" {
		fmt.Println("Error: Reality PBK is required; refusing insecure SNI-as-key fallback")
		os.Exit(1)
	}

	return cfg
}

func loadConfigFromFile(filename string) *Config {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("[CONFIG] Failed to read config file: %v", err)
		return nil
	}

	var cfg struct {
		ServerAddr       string   `json:"server"`
		BackupServers    []string `json:"backup_servers"`
		SNI              string   `json:"sni"`
		PBK              string   `json:"pbk"`
		User             string   `json:"user"`
		LocalPort        string   `json:"local"`
		Tun              bool     `json:"tun"`
		TunName          string   `json:"tun_name"`
		TunAddr          string   `json:"tun_addr"`
		TunGw            string   `json:"tun_gw"`
		TunMask          string   `json:"tun_mask"`
		TunDNS           string   `json:"tun_dns"`
		KillSwitch       bool     `json:"kill_switch"`
		Transport        string   `json:"transport"`
		Path             string   `json:"path"`
		Mode             string   `json:"mode"`
		ContentType      string   `json:"content_type"`
		TrafficMode      string   `json:"traffic_mode"`
		UDPProto         string   `json:"udp_proto"`
		TCPProto         string   `json:"tcp_proto"`
		RouteMode        string   `json:"route_mode"`
		ProxyApps        []string `json:"proxy_apps"`
		BypassApps       []string `json:"bypass_apps"`
		ProxyDomains     []string `json:"proxy_domains"`
		DirectDomains    []string `json:"direct_domains"`
		ServerPubKey     string   `json:"server_pub_key"`
		WireVersion      int      `json:"wire_version,omitempty"`
		UDPMode          string   `json:"udp_mode"`
		UpMbps           uint64   `json:"up_mbps"`
		DownMbps         uint64   `json:"down_mbps"`
		MTU              int      `json:"mtu"`
		AllowLAN         bool     `json:"allow_lan"`
		BlockIPv6        bool     `json:"block_ipv6"`
		Mux              bool     `json:"mux"`
		LogLevel         string   `json:"log_level"`
		FakeDNS          *bool    `json:"fake_dns"`
		TrafficPadding   *bool    `json:"traffic_padding"`
		AutoFallback     *bool    `json:"auto_fallback"`
		PortHopping      *bool    `json:"port_hopping"`
		RemoteDNS        *bool    `json:"remote_dns"`
		DecoyTraffic     *bool    `json:"decoy_traffic"`
		ZeroRTT          *bool    `json:"zero_rtt"`
		Fingerprint      string   `json:"fingerprint"`
		PaddingEnabled   *bool    `json:"padding_enabled"`
		MinPadding       int      `json:"min_padding"`
		MaxPadding       int      `json:"max_padding"`
		ChaffingEnabled  *bool    `json:"chaffing_enabled"`
		ChaffingInterval int      `json:"chaffing_interval"`
		ChaffingMinBytes int      `json:"chaffing_min_bytes"`
		ChaffingMaxBytes int      `json:"chaffing_max_bytes"`
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[CONFIG] Failed to parse config JSON: %v", err)
		return nil
	}

	// Set defaults for missing fields
	if cfg.LocalPort == "" {
		cfg.LocalPort = "127.0.0.1:1080"
	}
	if cfg.TunName == "" {
		cfg.TunName = "AtlantVPN"
	}
	if cfg.TunAddr == "" {
		cfg.TunAddr = "10.254.1.2"
	}
	if cfg.TunGw == "" {
		cfg.TunGw = "10.254.1.1"
	}
	if cfg.TunMask == "" {
		cfg.TunMask = "255.255.255.0"
	}
	if cfg.TunDNS == "" {
		cfg.TunDNS = "1.1.1.1"
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1420
	}
	if cfg.Transport == "" {
		cfg.Transport = "reality"
	}
	if cfg.Path == "" {
		cfg.Path = "/api/v1/sync"
	}
	if cfg.Mode == "" {
		cfg.Mode = "stream"
	}
	if cfg.ContentType == "" {
		cfg.ContentType = "application/octet-stream"
	}
	if cfg.TrafficMode == "" {
		cfg.TrafficMode = "split"
	}
	if cfg.RouteMode == "" {
		cfg.RouteMode = "all"
	}

	if cfg.SNI == "" {
		log.Printf("[CONFIG] Missing required SNI field")
		return nil
	}

	// Align transport and TCP protocol
	tcpProto := strings.ToLower(cfg.TCPProto)
	transport := strings.ToLower(cfg.Transport)
	if transport == "xhttp" {
		tcpProto = "xhttp"
	} else if transport == "" {
		transport = "reality"
	}
	if tcpProto == "" {
		tcpProto = "reality"
	}

	fakeDNS := true
	if cfg.FakeDNS != nil {
		fakeDNS = *cfg.FakeDNS
	}
	trafficPadding := true
	if cfg.TrafficPadding != nil {
		trafficPadding = *cfg.TrafficPadding
	}
	autoFallback := true
	if cfg.AutoFallback != nil {
		autoFallback = *cfg.AutoFallback
	}
	portHopping := false
	if cfg.PortHopping != nil {
		portHopping = *cfg.PortHopping
	}
	remoteDNS := true
	if cfg.RemoteDNS != nil {
		remoteDNS = *cfg.RemoteDNS
	}
	decoyTraffic := false
	if cfg.DecoyTraffic != nil {
		decoyTraffic = *cfg.DecoyTraffic
	}
	zeroRTT := true
	if cfg.ZeroRTT != nil {
		zeroRTT = *cfg.ZeroRTT
	}

	fingerprint := "firefox"
	if cfg.Fingerprint != "" {
		fingerprint = cfg.Fingerprint
	}
	paddingEnabled := true
	if cfg.PaddingEnabled != nil {
		paddingEnabled = *cfg.PaddingEnabled
	}
	minPadding := 32
	if cfg.MinPadding > 0 {
		minPadding = cfg.MinPadding
	}
	maxPadding := 256
	if cfg.MaxPadding > 0 {
		maxPadding = cfg.MaxPadding
	}
	chaffingEnabled := true
	if cfg.ChaffingEnabled != nil {
		chaffingEnabled = *cfg.ChaffingEnabled
	}
	chaffingInterval := 10
	if cfg.ChaffingInterval > 0 {
		chaffingInterval = cfg.ChaffingInterval
	}
	chaffingMinBytes := 16
	if cfg.ChaffingMinBytes > 0 {
		chaffingMinBytes = cfg.ChaffingMinBytes
	}
	chaffingMaxBytes := 64
	if cfg.ChaffingMaxBytes > 0 {
		chaffingMaxBytes = cfg.ChaffingMaxBytes
	}

	if minPadding > maxPadding {
		minPadding, maxPadding = maxPadding, minPadding
	}
	if chaffingMinBytes > chaffingMaxBytes {
		chaffingMinBytes, chaffingMaxBytes = chaffingMaxBytes, chaffingMinBytes
	}
	udpProto := cfg.UDPProto
	if udpProto == "" && cfg.UDPMode != "" {
		udpProto = cfg.UDPMode
	}

	log.Printf("[CONFIG] Config loaded from %s (Transport=%s, TCPProto=%s, Fingerprint=%s)", filename, transport, tcpProto, fingerprint)
	if cfg.WireVersion == 0 {
		cfg.WireVersion = 4
	}
	return &Config{
		ServerAddr:       cfg.ServerAddr,
		BackupServers:    cfg.BackupServers,
		SNI:              cfg.SNI,
		PBK:              cfg.PBK,
		User:             strings.TrimSpace(cfg.User),
		LocalPort:        cfg.LocalPort,
		Tun:              cfg.Tun,
		TunName:          cfg.TunName,
		TunAddr:          cfg.TunAddr,
		TunGw:            cfg.TunGw,
		TunMask:          cfg.TunMask,
		TunDNS:           cfg.TunDNS,
		KillSwitch:       cfg.KillSwitch,
		Transport:        transport,
		Path:             cfg.Path,
		Mode:             cfg.Mode,
		ContentType:      cfg.ContentType,
		TrafficMode:      cfg.TrafficMode,
		UDPProto:         udpProto,
		UDPMode:          cfg.UDPMode,
		TCPProto:         tcpProto,
		RouteMode:        cfg.RouteMode,
		ProxyApps:        cfg.ProxyApps,
		BypassApps:       cfg.BypassApps,
		ProxyDomains:     cfg.ProxyDomains,
		DirectDomains:    cfg.DirectDomains,
		ServerPubKey:     cfg.ServerPubKey,
		WireVersion:      cfg.WireVersion,
		UpMbps:           cfg.UpMbps,
		DownMbps:         cfg.DownMbps,
		MTU:              cfg.MTU,
		AllowLAN:         cfg.AllowLAN,
		BlockIPv6:        cfg.BlockIPv6,
		Mux:              cfg.Mux,
		LogLevel:         cfg.LogLevel,
		FakeDNS:          fakeDNS,
		TrafficPadding:   trafficPadding,
		AutoFallback:     autoFallback,
		PortHopping:      portHopping,
		RemoteDNS:        remoteDNS,
		DecoyTraffic:     decoyTraffic,
		ZeroRTT:          zeroRTT,
		Fingerprint:      fingerprint,
		PaddingEnabled:   paddingEnabled,
		MinPadding:       minPadding,
		MaxPadding:       maxPadding,
		ChaffingEnabled:  chaffingEnabled,
		ChaffingInterval: chaffingInterval,
		ChaffingMinBytes: chaffingMinBytes,
		ChaffingMaxBytes: chaffingMaxBytes,
	}
}

var (
	session         *yamux.Session
	mu              sync.Mutex
	sessionCond     = sync.NewCond(&mu)
	originalGateway string
	lastConnectTime time.Time
	isConnecting    bool
	sessionDead     bool
	activeCfg       *Config
)

func main() {
	cfg := parseConfig()
	InitCoreLogger(cfg.LogLevel)
	activeCfg = cfg

	// Discover default physical outbound IP so SOCKS5 and non-TUN modes bind directly to physical interface
	if physicalLocalIP == nil {
		_, physIP, err := getDefaultGateway("")
		if err == nil && physIP != "" {
			physicalLocalIP = net.ParseIP(physIP)
			log.Printf("[NET] Default physical interface IP detected: %s", physicalLocalIP)
		}
	}

	// Session health checker & Chaffing background noise
	go sessionHealthChecker()
	go startChaffingWorker(cfg)

	if cfg.Tun {
		if !amAdmin() {
			log.Printf("[TUN] Administrator privileges are required for TUN mode. Requesting UAC elevation...")
			runMeElevated()
			os.Exit(0)
		}
		// Also launch local SOCKS5 proxy concurrently for local apps, browser proxying, and in-tunnel speedtest
		go startSocks5(cfg)
		// TUN mode: intercept system traffic
		startTun(cfg)
	} else {
		// SOCKS5 proxy mode
		startSocks5(cfg)
	}
}

func sessionHealthChecker() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		var sessToPing *yamux.Session
		mu.Lock()
		if activeCfg != nil && activeCfg.Mux && session != nil && !session.IsClosed() {
			if time.Since(lastConnectTime) > 5*time.Minute {
				sessToPing = session
			}
		}
		mu.Unlock()

		if sessToPing != nil {
			if _, err := sessToPing.Ping(); err != nil {
				log.Printf("[HEALTH] Yamux session ping failed (%v), marking session dead", err)
				mu.Lock()
				if session == sessToPing {
					sessToPing.Close()
					session = nil
					sessionDead = true
					sessionCond.Broadcast()
				}
				mu.Unlock()
			}
		}
	}
}

func amAdmin() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

func runMeElevated() {
	verb := "runas"
	exe, err := os.Executable()
	if err != nil {
		log.Printf("[UAC] Failed to determine executable: %v", err)
		return
	}
	cwd, _ := os.Getwd()

	var escapedArgs []string
	for _, a := range os.Args[1:] {
		escapedArgs = append(escapedArgs, windows.EscapeArg(a))
	}
	args := strings.Join(escapedArgs, " ")

	verbPtr, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		return
	}
	exePtr, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return
	}
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argsPtr, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		return
	}

	var showCmd int32 = 1 // SW_NORMAL
	if err := windows.ShellExecute(0, verbPtr, exePtr, argsPtr, cwdPtr, showCmd); err != nil {
		log.Printf("[UAC] ShellExecute elevation error: %v", err)
	}
}

func startSocks5(cfg *Config) {
	conf := &socks5.Config{
		Resolver: remoteResolver{},
		Rewriter: remoteRewriter{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			type dialResult struct {
				conn net.Conn
				err  error
			}
			resCh := make(chan dialResult, 1)
			go func() {
				c, err := dialAndWriteHeader(cfg, network, addr)
				resCh <- dialResult{conn: c, err: err}
			}()

			select {
			case <-ctx.Done():
				go func() {
					res := <-resCh
					if res.conn != nil {
						res.conn.Close()
					}
				}()
				return nil, ctx.Err()
			case res := <-resCh:
				return res.conn, res.err
			}
		},
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Printf("[SOCKS5] Failed to create SOCKS5 server: %v", err)
		return
	}
	listenAddr, err := socksBindAddress(cfg.LocalPort, cfg.AllowLAN)
	if err != nil {
		log.Printf("[SOCKS5] Refusing unsafe listen address: %v", err)
		return
	}
	log.Printf("[SOCKS5] SOCKS5 server listening on %s (AllowLAN=%v)", listenAddr, cfg.AllowLAN)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[SOCKS5] Failed to listen on %s: %v", listenAddr, err)
		return
	}
	defer ln.Close()

	if err := server.Serve(ln); err != nil {
		log.Printf("[SOCKS5] Server error: %v", err)
	}
}
