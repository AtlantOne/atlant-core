package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	physicalGateway   string
	physicalIfIdx     string
	physicalLocalIP   net.IP
	directRoutes      sync.Map // ipStr -> int64 (last seen unix)
	directRoutesCount atomic.Int64
)

func ensureDirectRoute(ipStr string) {
	if ipStr == "" || physicalGateway == "" {
		return
	}
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return
	}
	ip4 := ip.To4()
	if ip4[0] == 198 && (ip4[1]&0xFE) == 18 {
		return // 198.18.0.0/15 FakeDNS pool must NEVER be routed to physical gateway
	}
	now := time.Now().Unix()
	if val, loaded := directRoutes.Load(ipStr); loaded {
		if now-val.(int64) > 300 {
			directRoutes.Store(ipStr, now)
		}
		return
	}

	// Prune directRoutes if too large (> 2048 entries)
	if directRoutesCount.Load() > 2048 {
		pruneDirectRoutes()
	}

	log.Printf("[ROUTE-DIRECT] Adding host bypass route for %s via %s (if=%s)", ipStr, physicalGateway, physicalIfIdx)
	if err := addOwnedRoute(routeSpec{ipStr, "255.255.255.255", physicalGateway, physicalIfIdx}); err != nil {
		log.Printf("[ROUTE-DIRECT] Cannot add bypass route: %v", err)
		return
	}
	if _, loaded := directRoutes.LoadOrStore(ipStr, now); !loaded {
		directRoutesCount.Add(1)
	}
}

func pruneDirectRoutes() {
	now := time.Now().Unix()
	var toDelete []string
	directRoutes.Range(func(key, value any) bool {
		if ts, ok := value.(int64); ok && now-ts > 600 {
			toDelete = append(toDelete, key.(string))
		}
		return true
	})
	for _, ip := range toDelete {
		directRoutes.Delete(ip)
		directRoutesCount.Add(-1)
		removeOwnedRoute(routeSpec{ip, "255.255.255.255", physicalGateway, physicalIfIdx})
	}
}

// getInterfaceIndex returns the numeric index of a network interface by name.
// Retries briefly because Windows may take a moment to register a newly created Wintun adapter.
func getInterfaceIndex(name string) string {
	for attempt := 0; attempt < 10; attempt++ {
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				if strings.EqualFold(iface.Name, name) {
					return strconv.Itoa(iface.Index)
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ""
}

// getInterfaceIndexByIP finds the interface index for a given local IPv4 address.
func getInterfaceIndexByIP(ipStr string) string {
	for attempt := 0; attempt < 10; attempt++ {
		if index := findInterfaceIndexByIP(ipStr); index != "" {
			return index
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ""
}

func findInterfaceIndexByIP(ipStr string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.String() == ipStr {
				return strconv.Itoa(iface.Index)
			}
		}
	}
	return ""
}

func configureInterface(cfg *Config) error {
	log.Printf("[TUN] Configuring interface '%s' with IP %s (gw=%s)", cfg.TunName, cfg.TunAddr, cfg.TunGw)
	cmd := exec.Command("netsh", "interface", "ip", "set", "address", "name="+cfg.TunName, "static", cfg.TunAddr, cfg.TunMask, cfg.TunGw, "1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP address: %v, output: %s", err, string(out))
	}

	dnsServer := cfg.TunDNS
	if dnsServer == "" {
		dnsServer = "1.1.1.1"
	}
	log.Printf("[TUN] Setting DNS to %s", dnsServer)
	cmd = exec.Command("netsh", "interface", "ip", "set", "dns", "name="+cfg.TunName, "static", dnsServer)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[TUN] Warning: failed to set DNS: %v, output: %s", err, string(out))
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	if out, err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", cfg.TunName, fmt.Sprintf("mtu=%d", mtu), "store=active").CombinedOutput(); err != nil {
		log.Printf("[TUN] Warning: set subinterface MTU failed: %v, out: %s", err, string(out))
	}

	if cfg.BlockIPv6 {
		if err := installIPv6Guard(); err != nil {
			return err
		}
	}
	return nil
}

func resetDNS(cfg *Config) {
	log.Printf("[TUN] Resetting DNS settings")

	if cfg != nil && cfg.TunName != "" {
		cmd := exec.Command("netsh", "interface", "ip", "set", "dns", "name="+cfg.TunName, "source=dhcp")
		_ = cmd.Run()
	}

	flushCmd := exec.Command("ipconfig", "/flushdns")
	_ = flushCmd.Run()
}

func configureRoutes(cfg *Config, serverIPs []net.IP) error {
	routeMu.Lock()
	routesClosing = false
	routeMu.Unlock()
	defaultGW, physIfaceIP, err := getDefaultGateway(cfg.TunAddr)
	if err != nil {
		return fmt.Errorf("failed to get physical gateway: %w", err)
	}
	originalGateway, physicalGateway = defaultGW, defaultGW
	physicalLocalIP = net.ParseIP(physIfaceIP)
	physicalIfIdx = getInterfaceIndexByIP(physIfaceIP)
	tunIndex := getInterfaceIndex(cfg.TunName)
	if physicalIfIdx == "" || tunIndex == "" {
		return fmt.Errorf("interface index unavailable: physical IP=%q index=%q gateway=%q; TUN name=%q index=%q", physIfaceIP, physicalIfIdx, defaultGW, cfg.TunName, tunIndex)
	}
	for _, ip := range serverIPs {
		if ip4 := ip.To4(); ip4 != nil {
			route := routeSpec{ip4.String(), "255.255.255.255", defaultGW, physicalIfIdx}
			if err := addOwnedRoute(route); err != nil {
				return fmt.Errorf("exclude server route: %w", err)
			}
			pinOwnedRoute(route)
		}
	}
	if cfg.KillSwitch {
		physicalDefault := routeSpec{"0.0.0.0", "0.0.0.0", defaultGW, physicalIfIdx}
		routeMu.Lock()
		err = runRoute(physicalDefault.args("delete")...)
		if err == nil {
			removedDefaultRoute = &physicalDefault
		}
		routeMu.Unlock()
		if err != nil {
			return fmt.Errorf("remove physical default route: %w", err)
		}
		if err := addOwnedRoute(routeSpec{"0.0.0.0", "0.0.0.0", cfg.TunGw, tunIndex}); err != nil {
			return err
		}
	} else {
		for _, destination := range []string{"0.0.0.0", "128.0.0.0"} {
			if err := addOwnedRoute(routeSpec{destination, "128.0.0.0", cfg.TunGw, tunIndex}); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanupRoutes(cfg *Config) {
	defer func() {
		if err := removeIPv6Guard(); err != nil {
			log.Printf("[TUN] IPv6 guard retained after cleanup error: %v", err)
		}
	}()
	routeMu.Lock()
	routesClosing = true
	for route := range ownedRoutes {
		if err := runRoute(route.args("delete")...); err != nil {
			log.Printf("[TUN] Route cleanup: %v", err)
		}
		delete(ownedRoutes, route)
	}
	if removedDefaultRoute != nil {
		if err := runRoute(removedDefaultRoute.args("add")...); err != nil {
			log.Printf("[TUN] Restore physical gateway: %v", err)
		}
		removedDefaultRoute = nil
	}
	routeMu.Unlock()
	directRoutes.Range(func(key, value any) bool { directRoutes.Delete(key); return true })
	directRoutesCount.Store(0)
	resetDNS(cfg)
	log.Println("[TUN] Owned route cleanup complete")
}

func getDefaultGateway(ignoreInterfaceIP string) (string, string, error) {
	// First probe active outgoing route to public DNS to identify the physical local IP
	var probeLocalIP string
	if testConn, err := net.DialTimeout("udp", "1.1.1.1:53", 600*time.Millisecond); err == nil {
		if udpAddr, ok := testConn.LocalAddr().(*net.UDPAddr); ok {
			ipStr := udpAddr.IP.String()
			// Only accept probe if it's not our TUN adapter IP
			if ipStr != ignoreInterfaceIP && !strings.HasPrefix(ipStr, "10.254.") && !strings.HasPrefix(ipStr, "172.19.") {
				probeLocalIP = ipStr
			}
		}
		testConn.Close()
	}

	cmd := exec.Command("route", "print", "0.0.0.0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}

	type routeCandidate struct {
		gwIP    string
		ifaceIP string
		metric  int
		isMatch bool
	}

	var candidates []routeCandidate

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if validDefaultRouteFields(fields) {
				gwIP := fields[2]
				ifaceIP := fields[3]
				metric := 9999
				if len(fields) >= 5 {
					if m, err := strconv.Atoi(fields[4]); err == nil {
						metric = m
					}
				}

				// пропускаем On-link, loopback, и диапазоны туннелей/виртуалок
				if strings.EqualFold(gwIP, "on-link") || gwIP == "0.0.0.0" {
					continue
				}
				if ifaceIP == ignoreInterfaceIP || strings.HasPrefix(ifaceIP, "10.254.1.") || strings.HasPrefix(ifaceIP, "172.19.0.") || strings.HasPrefix(ifaceIP, "172.18.0.") {
					continue
				}
				if gw := net.ParseIP(gwIP); gw != nil && !gw.IsLoopback() {
					cand := routeCandidate{
						gwIP:    gw.String(),
						ifaceIP: ifaceIP,
						metric:  metric,
						isMatch: (probeLocalIP != "" && ifaceIP == probeLocalIP),
					}
					candidates = append(candidates, cand)
				}
			}
		}
	}

	// If probe matched an exact interface in route table, that is our physical default route
	for _, c := range candidates {
		if c.isMatch {
			return c.gwIP, c.ifaceIP, nil
		}
	}

	// Sort candidates by metric ascending to pick the lowest metric
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].metric < candidates[j].metric
	})

	// Otherwise pick the best candidate (lowest metric)
	if len(candidates) > 0 {
		return candidates[0].gwIP, candidates[0].ifaceIP, nil
	}

	return "", "", fmt.Errorf("physical default gateway not found in route print output")
}

// Persistent route rows have no interface-address column. Never interpret
// their metric as a local IP when selecting the physical egress adapter.
func validDefaultRouteFields(fields []string) bool {
	if len(fields) != 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
		return false
	}
	for _, value := range fields[2:4] {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsLoopback() {
			return false
		}
	}
	metric, err := strconv.Atoi(fields[4])
	return err == nil && metric >= 0
}
