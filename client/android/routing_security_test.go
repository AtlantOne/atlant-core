//go:build android || (linux && atlanttest)

package atlant

import (
	"strings"
	"testing"
)

func TestRoutingRUSuffixWithTLSAndHTTP(t *testing.T) {
	SetRouteMode("bypass")
	SetDirectDomains("*.ru")
	t.Cleanup(func() { SetRouteMode("all"); SetDirectDomains("") })
	for _, name := range []string{"example.ru", "www.example.ru", "EXAMPLE.RU."} {
		data, err := buildClientHelloWithUTLS(strings.ToLower(name), make([]byte, 32), make([]byte, 32), "chrome")
		if err != nil {
			t.Fatal(err)
		}
		if ShouldRouteTarget("203.0.113.10:443", data) {
			t.Fatalf("visible TLS name %q ignored direct rule", name)
		}
		if ShouldRouteTarget("203.0.113.10:80", []byte("GET / HTTP/1.1\r\nHost: "+name+"\r\n\r\n")) {
			t.Fatalf("HTTP host %q ignored direct rule", name)
		}
	}
	for _, name := range []string{"ru.example.com", "example.ru.evil.com", "notru"} {
		if !ShouldRouteTarget(name+":443", nil) {
			t.Fatalf("non-Russian suffix %q bypassed VPN", name)
		}
	}
	if !needsDomainSniff("203.0.113.10:443") || needsDomainSniff("example.ru:443") {
		t.Fatal("incorrect QUIC sniff eligibility")
	}
}

func TestRoutingCachedNameCannotGrantDirectBypass(t *testing.T) {
	SetRouteMode("bypass")
	SetDirectDomains("allowed.example")
	t.Cleanup(func() { SetRouteMode("all"); SetDirectDomains(""); ipToDomain.Delete("203.0.113.10") })
	ipToDomain.Store("203.0.113.10", "allowed.example")
	if !ShouldRouteTarget("203.0.113.10:443", []byte("GET / HTTP/1.1\r\nHost: secret.example\r\n\r\n")) {
		t.Fatal("shared IP bypassed VPN")
	}
	if !ShouldRouteTarget("203.0.113.10:443", nil) {
		t.Fatal("cached domain allowed unknown connection")
	}
	if ShouldRouteTarget("203.0.113.10:443", []byte("GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")) {
		t.Fatal("explicit direct rule not honored")
	}
}

func TestRoutingUnknownNameStaysProtected(t *testing.T) {
	SetRouteMode("rules")
	SetProxyDomains("private.example")
	t.Cleanup(func() { SetRouteMode("all"); SetProxyDomains("") })
	for _, data := range [][]byte{nil, {22, 3, 1, 0, 200, 1}} {
		if !ShouldRouteTarget("203.0.113.10:443", data) {
			t.Fatal("unknown or partial hello went direct")
		}
	}
	if ShouldRouteTarget("other.example:443", nil) {
		t.Fatal("known nonmatching domain should retain direct rule semantics")
	}
}
