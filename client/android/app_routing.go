//go:build android || (linux && atlanttest)

package atlant

import (
	"net"
	"strconv"
	"sync"
)

// AppRouter is supplied by VpnService for mixed application/domain rules.
// Return 1 for a selected UID, 0 for a known other UID, -1 if unresolved.
type AppRouter interface {
	RouteConnection(protocol int, sourceIP string, sourcePort int, destinationIP string, destinationPort int) int
}

var appRouterMu sync.RWMutex
var appRouter AppRouter

func SetAppRouter(router AppRouter) {
	appRouterMu.Lock()
	defer appRouterMu.Unlock()
	appRouter = router
}

func mustProxyApp(conn net.Conn, protocol int) (protected bool) {
	appRouterMu.RLock()
	router := appRouter
	appRouterMu.RUnlock()
	if router == nil {
		return false
	}
	protected = true
	defer func() {
		if recover() != nil {
			protected = true
		}
	}()
	source, sport, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return true
	}
	destination, dport, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return true
	}
	sp, err := strconv.Atoi(sport)
	if err != nil {
		return true
	}
	dp, err := strconv.Atoi(dport)
	if err != nil {
		return true
	}
	return router.RouteConnection(protocol, source, sp, destination, dp) != 0
}
