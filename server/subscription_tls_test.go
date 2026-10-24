package main

import "testing"

func TestSubscriptionConfigRejectsCertificateMixupsAndVPNPort(t *testing.T) {
	c := SubscriptionConfig{Enabled: true, Listen: ":8443", PublicURL: "https://198.51.100.20:8443", TLS: SubscriptionTLSConfig{Mode: "acme-ip", Host: "198.51.100.20", CacheDir: "private-cache", AcceptTerms: true}}
	if err := validateSubscriptionConfig(c, ":443"); err != nil {
		t.Fatal(err)
	}
	if err := validateSubscriptionConfig(c, ":8443"); err == nil {
		t.Fatal("VPN port conflict accepted")
	}
	c.TLS.AcceptTerms = false
	if validateSubscriptionConfig(c, ":443") == nil {
		t.Fatal("terms not required")
	}
	c.TLS.AcceptTerms = true
	c.TLS.Mode = "acme-domain"
	if validateSubscriptionConfig(c, ":443") == nil {
		t.Fatal("IP with domain mode accepted")
	}
	c.TLS.Mode = "manual"
	if validateSubscriptionConfig(c, ":443") == nil {
		t.Fatal("missing manual pair accepted")
	}
}
