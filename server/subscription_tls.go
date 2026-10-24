package main

import (
	"atlant.local/protocol/certificates"
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type SubscriptionTLSConfig = certificates.Config

var activeSubscriptionCertificate atomic.Pointer[certificates.Manager]

func validateSubscriptionConfig(c SubscriptionConfig, vpnAddr string) error {
	if !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("subscription public_url must be an HTTPS origin")
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "0" {
		return errors.New("subscription listen requires a dedicated nonzero port")
	}
	_, vpnPort, _ := net.SplitHostPort(vpnAddr)
	if port == vpnPort {
		return errors.New("subscriptions must not use the VPN listener port")
	}
	if c.TLS.Host == "" || !strings.EqualFold(c.TLS.Host, u.Hostname()) {
		return errors.New("subscription TLS host must match public_url")
	}
	if strings.ContainsAny(c.TLS.Host, "/\\\r\n\t ") || len(c.TLS.Host) > 253 {
		return errors.New("invalid certificate identity")
	}
	switch c.TLS.Mode {
	case "manual":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("manual certificate and key paths required")
		}
	case "acme-ip", "acme-domain":
		if !c.TLS.AcceptTerms {
			return errors.New("explicit acceptance of ACME CA terms required")
		}
		ip := net.ParseIP(c.TLS.Host)
		if c.TLS.Mode == "acme-ip" && (ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return errors.New("public IP required for acme-ip")
		}
		if c.TLS.Mode == "acme-domain" && (ip != nil || !strings.Contains(c.TLS.Host, ".") || strings.Contains(c.TLS.Host, "*")) {
			return errors.New("domain required for acme-domain; wildcard not supported by HTTP-01")
		}
		if c.TLS.CacheDir == "" {
			return errors.New("private ACME cache directory required")
		}
		if c.TLS.ChallengeDir != "" && !filepath.IsAbs(c.TLS.ChallengeDir) {
			return errors.New("shared HTTP-01 challenge directory must be absolute")
		}
		if c.TLS.ChallengeListen != "" {
			_, p, e := net.SplitHostPort(c.TLS.ChallengeListen)
			if e != nil || p != "80" {
				return errors.New("HTTP-01 requires port 80")
			}
		}
	default:
		return errors.New("TLS mode must be manual, acme-ip or acme-domain")
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) error {
	return certificates.WritePrivateAtomic(path, data)
}

func startSubscriptionServer(c SubscriptionConfig) {
	if !c.Enabled {
		return
	}
	if err := validateSubscriptionConfig(c, cfg.ServerAddr); err != nil {
		log.Printf("[SUBSCRIPTION] Invalid settings: %v", err)
		return
	}
	m := certificates.New(c.TLS)
	activeSubscriptionCertificate.Store(m)
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		m.SetError("HTTPS listener unavailable")
		log.Printf("[SUBSCRIPTION] Listener unavailable; VPN unchanged: %v", err)
		return
	}
	defer ln.Close()
	defer m.SetListening(false)
	serviceCtx, stop := context.WithCancel(context.Background())
	defer stop()
	if c.TLS.Mode != "manual" {
		if c.TLS.ChallengeDir == "" {
			address := c.TLS.ChallengeListen
			if address == "" {
				address = ":80"
			}
			challengeListener, err := net.Listen("tcp", address)
			if err != nil {
				m.SetError("ACME HTTP-01 listener unavailable")
				log.Printf("[SUBSCRIPTION] ACME HTTP-01 listener unavailable; VPN unchanged: %v", err)
				return
			}
			challengeServer := &http.Server{Handler: http.HandlerFunc(m.ChallengeHandler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
			defer challengeServer.Close()
			go challengeServer.Serve(certificates.LimitListener(challengeListener, 64))
		}
		_ = m.Reload()
		issue := func() {
			if !m.RenewalDue(time.Now()) {
				return
			}
			ctx, cancel := context.WithTimeout(serviceCtx, 5*time.Minute)
			err := m.Ensure(ctx)
			cancel()
			if err != nil {
				log.Printf("[SUBSCRIPTION] ACME failed; existing certificate retained: %v", err)
			}
		}
		issue()
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-serviceCtx.Done():
					return
				case <-ticker.C:
					issue()
				}
			}
		}()
	} else if err := m.Reload(); err != nil {
		log.Printf("[SUBSCRIPTION] Manual certificate unavailable: %v", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", publicSubscriptionHandler)
	mux.HandleFunc("/quota/v1/budget", handleQuotaBudget)
	server := &http.Server{Addr: c.Listen, Handler: mux, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.GetCertificate}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("[SUBSCRIPTION] HTTPS-only subscription listener on %s; REALITY transport unchanged", c.Listen)
	m.SetListening(true)
	if err := server.ServeTLS(ln, "", ""); err != nil {
		log.Printf("[SUBSCRIPTION] Listener stopped: %v", err)
	}
}
func subscriptionCertificateStatus() map[string]any {
	if m := activeSubscriptionCertificate.Load(); m != nil {
		return m.Status()
	}
	return map[string]any{"listening": false}
}
