//go:build android || (linux && atlanttest)

package atlant

import (
	"net"
	"testing"
)

type testAppRouter func(int, string, int, string, int) int

func (f testAppRouter) RouteConnection(p int, s string, sp int, d string, dp int) int {
	return f(p, s, sp, d, dp)
}

type appRoutingConn struct{ net.Conn }

func (appRoutingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 12345}
}
func (appRoutingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
}

func TestAppRoutingProtectsUnknownOwner(t *testing.T) {
	t.Cleanup(func() { SetAppRouter(nil) })
	for _, verdict := range []int{-1, 0, 1} {
		SetAppRouter(testAppRouter(func(p int, s string, sp int, d string, dp int) int {
			if p != 6 || s != "10.0.0.2" || sp != 12345 || d != "1.1.1.1" || dp != 443 {
				t.Fatalf("incorrect connection tuple: %d %s:%d -> %s:%d", p, s, sp, d, dp)
			}
			return verdict
		}))
		if got := mustProxyApp(appRoutingConn{}, 6); got != (verdict != 0) {
			t.Fatalf("owner verdict %d: protected=%v", verdict, got)
		}
	}
	SetAppRouter(testAppRouter(func(int, string, int, string, int) int { panic("callback unavailable") }))
	if !mustProxyApp(appRoutingConn{}, 6) {
		t.Fatal("callback panic must not bypass VPN")
	}
	SetAppRouter(nil)
	if mustProxyApp(appRoutingConn{}, 6) {
		t.Fatal("disabled application rules should defer to domain routing")
	}
}
