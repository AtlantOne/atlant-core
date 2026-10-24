package main

import (
	"atlant.local/protocol/settings"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	TunDNS           string   `json:"tun_dns"`
	TunIPv6Addr      string   `json:"tun_ipv6_addr,omitempty"`
	TunDNSIPv6       string   `json:"tun_dns_ipv6,omitempty"`
	DisableIPv6      bool     `json:"disable_ipv6,omitempty"`
	Transport        string   `json:"transport"`
	Path             string   `json:"path"`
	Mode             string   `json:"mode"`
	ContentType      string   `json:"content_type"`
	TrafficMode      string   `json:"traffic_mode"` // "split", "tcp", "udp"
	UDPProto         string   `json:"udp_proto"`    // "quic", "tcp"
	UDPMode          string   `json:"udp_mode"`
	TCPProto         string   `json:"tcp_proto"` // "reality", "xhttp"
	ServerPubKey     string   `json:"server_pub_key"`
	WireVersion      int      `json:"wire_version,omitempty"`
	MTU              int      `json:"mtu"`
	Mux              bool     `json:"mux"`
	LogLevel         string   `json:"log_level"`
	FakeDNS          bool     `json:"fake_dns"`
	TrafficPadding   bool     `json:"traffic_padding"`
	Fingerprint      string   `json:"fingerprint"`
	PaddingEnabled   bool     `json:"padding_enabled"`
	MinPadding       int      `json:"min_padding"`
	MaxPadding       int      `json:"max_padding"`
	ChaffingEnabled  bool     `json:"chaffing_enabled"`
	ChaffingInterval int      `json:"chaffing_interval"`
	ChaffingMinBytes int      `json:"chaffing_min_bytes"`
	ChaffingMaxBytes int      `json:"chaffing_max_bytes"`
}

func parseConfig() *Config {
	cfg := &Config{
		WireVersion:      6,
		ServerAddr:       "127.0.0.1:443",
		LocalPort:        "127.0.0.1:1080",
		TunName:          "atlant0",
		TunAddr:          "10.254.1.2/24",
		TunDNS:           "1.1.1.1",
		Transport:        "reality",
		Path:             "/api/v1/sync",
		Mode:             "stream",
		TrafficMode:      "split",
		TCPProto:         "reality",
		UDPProto:         "quic",
		MTU:              1380,
		Mux:              false,
		LogLevel:         "info",
		FakeDNS:          true,
		TrafficPadding:   true,
		Fingerprint:      "firefox",
		PaddingEnabled:   true,
		MinPadding:       32,
		MaxPadding:       256,
		ChaffingEnabled:  true,
		ChaffingInterval: 10,
		ChaffingMinBytes: 16,
		ChaffingMaxBytes: 64,
	}

	configFileFlag := flag.String("c", "", "Path to JSON config file")
	configURLFlag := flag.String("config", "", "atlant://... config URL or JSON file path")
	serverFlag := flag.String("server", "", "Server address (host:port)")
	sniFlag := flag.String("sni", "", "SNI domain for TLS (e.g. www.microsoft.com)")
	pbkFlag := flag.String("pbk", "", "Reality PBK pre-shared key")
	userFlag := flag.String("user", "", "Username for authentication")
	serverKeyFlag := flag.String("server-pub-key", "", "Server static X25519 public key (Reality 2-ECDH)")
	localFlag := flag.String("local", "", "Local SOCKS5 listen address (default :1080)")
	tunFlag := flag.Bool("tun", false, "Enable Linux TUN VPN mode")
	tunNameFlag := flag.String("tun-name", "", "Linux TUN interface name (default atlant0)")
	tunAddrFlag := flag.String("tun-addr", "", "Linux TUN IP/CIDR (default 10.254.1.2/24)")
	transportFlag := flag.String("transport", "", "Transport protocol: reality, xhttp, quic")
	pathFlag := flag.String("path", "", "XHTTP URL path endpoint")
	modeFlag := flag.String("mode", "", "XHTTP mode: stream or packet-up")
	fingerprintFlag := flag.String("fingerprint", "", "uTLS ClientHello fingerprint profile: chrome, firefox, safari, ios, edge, randomized")
	paddingFlag := flag.Bool("padding", true, "Enable dynamic packet length padding")
	minPaddingFlag := flag.Int("min-padding", 0, "Minimum padding bytes")
	maxPaddingFlag := flag.Int("max-padding", 0, "Maximum padding bytes")
	chaffingFlag := flag.Bool("chaffing", true, "Enable background chaffing micro-noise")
	chaffingIntervalFlag := flag.Int("chaffing-interval", 0, "Chaffing interval in seconds")
	muxFlag := flag.Bool("mux", false, "Enable Yamux stream multiplexing (default false = direct 1-to-1)")
	logLevelFlag := flag.String("loglevel", "", "Log level: debug, info, warn, error, none")

	flag.Parse()

	// Check if config file or URL was specified
	fileToLoad := *configFileFlag
	if fileToLoad == "" && *configURLFlag != "" {
		if strings.HasPrefix(*configURLFlag, "atlant://") {
			if urlCfg := parseAtlantURL(*configURLFlag); urlCfg != nil {
				cfg = urlCfg
			}
		} else {
			fileToLoad = *configURLFlag
		}
	}

	if fileToLoad == "" {
		candidates := []string{"atlant_config.json", "config.json"}
		if exe, err := os.Executable(); err == nil {
			dir := filepath.Dir(exe)
			candidates = append(candidates, filepath.Join(dir, "atlant_config.json"), filepath.Join(dir, "config.json"))
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				fileToLoad = c
				break
			}
		}
	}

	if fileToLoad != "" {
		if fileCfg := loadConfigFromFile(fileToLoad); fileCfg != nil {
			cfg = fileCfg
		}
	}

	// Override with CLI flags
	if *serverFlag != "" {
		cfg.ServerAddr = *serverFlag
	}
	if *sniFlag != "" {
		cfg.SNI = *sniFlag
	}
	if *pbkFlag != "" {
		cfg.PBK = *pbkFlag
	}
	if *userFlag != "" {
		cfg.User = strings.TrimSpace(*userFlag)
	}
	if *serverKeyFlag != "" {
		cfg.ServerPubKey = strings.TrimSpace(*serverKeyFlag)
	}
	if *localFlag != "" {
		cfg.LocalPort = *localFlag
	}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "tun" {
			cfg.Tun = *tunFlag
		}
		if f.Name == "padding" {
			cfg.PaddingEnabled = *paddingFlag
		}
		if f.Name == "chaffing" {
			cfg.ChaffingEnabled = *chaffingFlag
		}
		if f.Name == "mux" {
			cfg.Mux = *muxFlag
		}
	})
	if *tunNameFlag != "" {
		cfg.TunName = *tunNameFlag
	}
	if *tunAddrFlag != "" {
		cfg.TunAddr = *tunAddrFlag
	}
	if *transportFlag != "" {
		cfg.Transport = *transportFlag
	}
	if *pathFlag != "" {
		cfg.Path = *pathFlag
	}
	if *modeFlag != "" {
		cfg.Mode = *modeFlag
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
	if *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}

	cfg.MinPadding, cfg.MaxPadding = settings.PaddingRange(cfg.MinPadding, cfg.MaxPadding)
	cfg.ChaffingMinBytes, cfg.ChaffingMaxBytes = settings.PaddingRange(cfg.ChaffingMinBytes, cfg.ChaffingMaxBytes)

	if cfg.SNI == "" {
		fmt.Println("Atlant VPN Linux Client")
		fmt.Println("Usage: atlant_client_linux -server 1.2.3.4:443 -sni www.microsoft.com -pbk <key> [-tun] [-local :1080]")
		flag.PrintDefaults()
		os.Exit(1)
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
		log.Printf("[CONFIG] Failed to read config file %s: %v", filename, err)
		return nil
	}

	cfg := &Config{
		WireVersion:      4,
		ServerAddr:       "127.0.0.1:443",
		LocalPort:        "127.0.0.1:1080",
		TunName:          "atlant0",
		TunAddr:          "10.254.1.2/24",
		TunDNS:           "1.1.1.1",
		Transport:        "reality",
		Path:             "/api/v1/sync",
		Mode:             "stream",
		TrafficMode:      "split",
		TCPProto:         "reality",
		UDPProto:         "quic",
		MTU:              1380,
		Mux:              false,
		LogLevel:         "info",
		FakeDNS:          true,
		TrafficPadding:   true,
		Fingerprint:      "firefox",
		PaddingEnabled:   true,
		MinPadding:       32,
		MaxPadding:       256,
		ChaffingEnabled:  true,
		ChaffingInterval: 10,
		ChaffingMinBytes: 16,
		ChaffingMaxBytes: 64,
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		log.Printf("[CONFIG] Failed to parse config JSON: %v", err)
		return nil
	}
	return cfg
}

func parseAtlantURL(link string) *Config {
	u, err := url.Parse(link)
	if err != nil {
		log.Printf("[CONFIG] Invalid URL: %v", err)
		return nil
	}

	cfg := &Config{
		ServerAddr:       u.Host,
		WireVersion:      4,
		LocalPort:        "127.0.0.1:1080",
		TunName:          "atlant0",
		TunAddr:          "10.254.1.2/24",
		TunDNS:           "1.1.1.1",
		Transport:        "reality",
		Path:             "/api/v1/sync",
		Mode:             "stream",
		TrafficMode:      "split",
		TCPProto:         "reality",
		UDPProto:         "quic",
		MTU:              1380,
		Mux:              false,
		LogLevel:         "info",
		FakeDNS:          true,
		TrafficPadding:   true,
		Fingerprint:      "firefox",
		PaddingEnabled:   true,
		MinPadding:       32,
		MaxPadding:       256,
		ChaffingEnabled:  true,
		ChaffingInterval: 10,
		ChaffingMinBytes: 16,
		ChaffingMaxBytes: 64,
	}

	q := u.Query()
	if value := q.Get("wire_version"); value != "" {
		version, err := strconv.Atoi(value)
		if err != nil || (version != 2 && version != 3 && version != 4 && version != 6 && version != 7) {
			return nil
		}
		cfg.WireVersion = version
	}
	if sni := q.Get("sni"); sni != "" {
		cfg.SNI = sni
	}
	if pbk := q.Get("pbk"); pbk != "" {
		cfg.PBK = pbk
	}
	if user := q.Get("user"); user != "" {
		cfg.User = user
	}
	if spk := q.Get("server_pub_key"); spk != "" {
		cfg.ServerPubKey = spk
	}
	if tr := q.Get("transport"); tr != "" {
		cfg.Transport = tr
	}
	if path := q.Get("path"); path != "" {
		cfg.Path = path
	}
	if fp := q.Get("fp"); fp != "" {
		cfg.Fingerprint = fp
	} else if fp := q.Get("fingerprint"); fp != "" {
		cfg.Fingerprint = fp
	}
	if pad := q.Get("padding"); pad == "false" || pad == "0" {
		cfg.PaddingEnabled = false
	}
	if chaff := q.Get("chaffing"); chaff == "false" || chaff == "0" {
		cfg.ChaffingEnabled = false
	}
	if mux := q.Get("mux"); mux == "true" || mux == "1" {
		cfg.Mux = true
	}
	if tun := q.Get("tun"); tun == "true" || tun == "1" {
		cfg.Tun = true
	}
	if intv, err := strconv.Atoi(q.Get("chaffing_interval")); err == nil && intv > 0 {
		cfg.ChaffingInterval = intv
	}

	return cfg
}
