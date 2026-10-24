package main

import (
	"atlant.local/protocol/tlsaudit"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestRetiredChromeProfileMigration(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var token [32]byte
	var baseline string
	for _, name := range []string{"chrome_144", "chrome", "chrome_auto", "chrome_133"} {
		hello, err := buildClientHelloWithUTLS("example.com", token[:], key.PublicKey().Bytes(), name)
		if err != nil {
			t.Fatal(name, err)
		}
		summary, err := tlsaudit.Summarize(hello)
		if err != nil {
			t.Fatal(err)
		}
		if baseline == "" {
			baseline = summary.StructuralKey()
		}
		if summary.StructuralKey() != baseline {
			t.Fatalf("%q did not select the measured Chrome 144 profile", name)
		}
		if len(summary.KeyShareSizes) != 2 || summary.KeyShareSizes[0] != 1216 || summary.KeyShareSizes[1] != 32 {
			t.Fatal("modern key shares missing", name)
		}
	}
	defaultHello, err := buildClientHelloWithUTLS("example.com", token[:], key.PublicKey().Bytes(), "")
	if err != nil {
		t.Fatal(err)
	}
	firefoxHello, err := buildClientHelloWithUTLS("example.com", token[:], key.PublicKey().Bytes(), "firefox")
	if err != nil {
		t.Fatal(err)
	}
	defaultSummary, err := tlsaudit.Summarize(defaultHello)
	if err != nil {
		t.Fatal(err)
	}
	firefoxSummary, err := tlsaudit.Summarize(firefoxHello)
	if err != nil {
		t.Fatal(err)
	}
	if defaultSummary.StructuralKey() != firefoxSummary.StructuralKey() {
		t.Fatal("empty profile must select Firefox")
	}
	if _, err := buildClientHelloWithUTLS("example.com", token[:], key.PublicKey().Bytes(), "chrome_999"); err == nil {
		t.Fatal("unknown profile must not silently use another profile")
	}
}
