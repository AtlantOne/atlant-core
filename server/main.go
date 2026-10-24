package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"
)

var cfg *Config
var debug bool

// Per-SNI RSA keys are generated and cached to avoid using one global key
// for all certificates (reduces fingerprinting risk).

// Popular cipher suites for SNI simulation
var cipherSuites = map[string][]uint16{
	"google.com": {
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0x1301, // TLS_AES_128_GCM_SHA256
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	},
	"microsoft.com": {
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
		0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	},
	"cloudflare.com": {
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0x1301, // TLS_AES_128_GCM_SHA256
		0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	},
	"default": {
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	},
}

func getCipherSuites(sni string) []uint16 {
	if suites, ok := cipherSuites[sni]; ok {
		return suites
	}

	parts := strings.Split(sni, ".")
	if len(parts) >= 2 {
		domain := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if suites, ok := cipherSuites[domain]; ok {
			return suites
		}
	}

	return cipherSuites["default"]
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Recovered in main: %v", r)
		}
	}()

	configFileFlag := flag.String("c", "", "Path to configuration file (JSON, e.g. config.json)")
	configFileLongFlag := flag.String("config-file", "", "Path to configuration file (JSON, e.g. config.json)")
	configStr := flag.String("config", "", "atlant://... URL configuration")
	sniFlag := flag.String("sni", "", "SNI domain for TLS (overrides config sni=)")
	addrFlag := flag.String("addr", "", "Listen address (overrides config listen/host) e.g. :443")
	transportFlag := flag.String("transport", "", "Transport protocol: auto, reality, xhttp")
	pathFlag := flag.String("path", "", "XHTTP URL path endpoint")
	modeFlag := flag.String("mode", "", "XHTTP mode: stream or packet-up")
	certFlag := flag.String("cert", "", "Path to TLS certificate file (e.g. Let's Encrypt / ZeroSSL)")
	keyFlag := flag.String("key", "", "Path to TLS private key file")
	serverKeyFlag := flag.String("server-key", "", "Path to server static X25519 key file (Reality 2-ECDH)")
	upMbpsFlag := flag.Uint64("up-mbps", 0, "Upload rate limit in Mbps (0 = unlimited / line speed)")
	downMbpsFlag := flag.Uint64("down-mbps", 0, "Download rate limit in Mbps (0 = unlimited / line speed)")
	apiAddrFlag := flag.String("api-addr", "", "Management REST API listen address (default 127.0.0.1:8080)")
	apiSecretFlag := flag.String("api-secret", "", "Optional secret token for API access")
	debugFlag := flag.Bool("debug", false, "Enable debug logging (sets loglevel to debug)")
	logLevelFlag := flag.String("loglevel", "", "Log level: debug, info, warn, error, none")
	command := flag.String("cmd", "", "Execute command and exit (e.g. 'getlink <name>')")
	flag.Parse()

	// Determine configuration source:
	// Priority: Explicit config URL > Explicit config file > Auto-discovered config.json > Production defaults
	cfgFilePath := *configFileFlag
	if cfgFilePath == "" {
		cfgFilePath = *configFileLongFlag
	}
	discoveredConfig := FindConfigFile(cfgFilePath)

	if *configStr != "" {
		var parseErr error
		cfg, parseErr = ParseAtlantURL(*configStr)
		if parseErr != nil {
			log.Fatalf("[CONFIG] Failed to parse config URL: %v", parseErr)
		}
	} else if discoveredConfig != "" {
		var loadErr error
		cfg, loadErr = LoadConfigFromFile(discoveredConfig)
		if loadErr != nil {
			log.Fatalf("[CONFIG] Failed to load config from %s: %v", discoveredConfig, loadErr)
		}
		log.Printf("[CONFIG] Loaded configuration from %s", discoveredConfig)
	} else {
		cfg = DefaultConfig()
	}

	// CLI flags override config file/URL settings
	if *sniFlag != "" {
		cfg.SNI = *sniFlag
	}
	if *addrFlag != "" {
		cfg.ServerAddr = *addrFlag
	}
	if *transportFlag != "" {
		cfg.Transport = *transportFlag
	}
	if *pathFlag != "" {
		cfg.Path = *pathFlag
		cfg.ServerPath = *pathFlag
	}
	if *modeFlag != "" {
		cfg.Mode = *modeFlag
	}
	if *certFlag != "" {
		cfg.CertFile = *certFlag
	}
	if *keyFlag != "" {
		cfg.KeyFile = *keyFlag
	}
	if *serverKeyFlag != "" {
		cfg.ServerKeyFile = *serverKeyFlag
	}
	if *upMbpsFlag > 0 {
		cfg.UpMbps = *upMbpsFlag
	}
	if *downMbpsFlag > 0 {
		cfg.DownMbps = *downMbpsFlag
	}
	if *apiAddrFlag != "" {
		cfg.APIAddr = *apiAddrFlag
	}
	if *apiSecretFlag != "" {
		cfg.APISecret = *apiSecretFlag
	}
	if *debugFlag {
		cfg.Debug = true
		cfg.LogLevel = "debug"
	}
	if *logLevelFlag != "" {
		cfg.LogLevel = *logLevelFlag
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "error"
	}
	if cfg.LogLevel == "debug" {
		cfg.Debug = true
	}
	debug = cfg.Debug

	InitServerLogger(cfg.LogLevel)

	if err := loadUsers(cfg.UsersFile); err != nil {
		log.Fatalf("[USERS] Cannot initialize persistent user database: %v", err)
	}
	defer closeUsersStore()
	if err := initServerIdentityForCatalog(cfg); err != nil {
		log.Fatalf("[SECURITY] Cannot load persistent server identity: %v", err)
	}
	initServerKeys(cfg.SNI)

	if *command != "" {
		handleCommand(*command)
		return
	}
	installUsersShutdownHandler(cfg.UsersFile)
	if cfg.WireVersion != 0 && cfg.WireVersion != 2 && cfg.WireVersion != 3 && cfg.WireVersion != 4 && cfg.WireVersion != 6 && cfg.WireVersion != 7 {
		log.Fatal("unsupported wire_version")
	}
	if (cfg.WireVersion == 4 || cfg.WireVersion == 6 || cfg.WireVersion == 7) && cfg.LegacyWire {
		log.Fatal("wire4/wire6/wire7 require legacy_wire=false; no legacy admission fallback")
	}
	if cfg.WireVersion == 3 || cfg.WireVersion == 4 || cfg.WireVersion == 6 {
		gate, err := newAdmissionGate()
		if err != nil {
			log.Fatal(err)
		}
		activeAdmission.Store(gate)
	}

	// SQLite is the sole authority; legacy JSON is never watched/reimported.
	catalog, err := prepareNativeInboundCatalog(context.Background(), cfg)
	if err == nil {
		catalog, err = bootNativeInboundCatalog(context.Background(), catalog)
	}
	if err != nil {
		log.Fatalf("[INBOUNDS] Cannot prepare persistent listeners: %v", err)
	}
	if err := initQuotaWorker(cfg.Quota); err != nil {
		log.Fatalf("[QUOTA] Initialization failed: %v", err)
	}
	var native *inboundController
	if catalog != nil {
		native, err = startInboundController(context.Background(), *catalog)
		if err != nil {
			log.Fatalf("[INBOUNDS] Cannot start persistent listeners: %v", err)
		}
		native.persist = persistAppliedInboundCatalog
		if err := native.persist(*catalog); err != nil {
			native.Close()
			log.Fatalf("[INBOUNDS] Cannot persist applied listeners: %v", err)
		}
		activeInboundController.Store(native)
		defer activeInboundController.CompareAndSwap(native, nil)
		defer native.Close()
	}
	go runQuotaWorker()
	go startUserCommandLoop()
	go startStatsFlusher(cfg.UsersFile)
	go enforceActiveUserLimits()
	go startAPIServer(cfg)
	go startSubscriptionServer(cfg.Subscriptions)
	go cleanupOldTokens()
	if native != nil {
		log.Printf("[INBOUNDS] Persistent catalog revision %d is active", catalog.Revision)
		if err := native.Wait(); err != nil {
			log.Fatalf("[INBOUNDS] Listener set stopped: %v", err)
		}
		return
	}

	host, port, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		host = ""
		port = cfg.ServerAddr
	}
	if port == "" {
		port = "443"
	}

	listenAddr := net.JoinHostPort(host, port)

	// запуск UDP сервера
	go startUDPVPNServer(listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("[FATAL] Failed to listen on %s: %v", listenAddr, err)
	}

	log.Printf("Reality TCP server listening on %s (SNI=%s)...", ln.Addr(), cfg.GetSNI())
	runtime := &tcpListenerRuntime{config: cfg, identity: serverStaticECDH, tcp: true, xhttp: true, legacyPath: true}
	if err := serveTCPVPNServer(context.Background(), ln, runtime); err != nil {
		log.Fatalf("[FATAL] TCP listener stopped: %v", err)
	}
}
