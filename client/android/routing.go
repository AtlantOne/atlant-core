//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"atlant.local/protocol/routepeek"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	routeMu       sync.RWMutex
	routeMode     string = "all" // "all", "rules", "bypass"
	proxyDomains  []string
	directDomains []string
	ipToDomain    sync.Map
)

// SetRouteMode sets routing strategy: "all", "rules" (only proxy rules), "bypass" (bypass direct rules).
func SetRouteMode(mode string) {
	routeMu.Lock()
	defer routeMu.Unlock()
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "proxy_apps" || m == "proxy" {
		m = "rules"
	} else if m == "bypass_apps" {
		m = "bypass"
	}
	routeMode = m
}

func isRouteModeAll() bool {
	routeMu.RLock()
	defer routeMu.RUnlock()
	return routeMode == "all" || routeMode == ""
}

// SetProxyDomains sets the list of domains or CIDRs to PROXY via VPN (used in "rules" mode).
func SetProxyDomains(domains string) {
	routeMu.Lock()
	defer routeMu.Unlock()
	proxyDomains = parseDomainsList(domains)
}

// SetDirectDomains sets the list of domains or CIDRs to BYPASS VPN (used in "bypass" mode).
func SetDirectDomains(domains string) {
	routeMu.Lock()
	defer routeMu.Unlock()
	directDomains = parseDomainsList(domains)
}

func parseDomainsList(text string) []string {
	var list []string
	for _, line := range strings.Split(text, "\n") {
		for _, part := range strings.Split(line, ",") {
			s := strings.ToLower(strings.TrimSpace(part))
			if s != "" && !strings.HasPrefix(s, "#") {
				list = append(list, s)
			}
		}
	}
	return list
}

func matchDomainPattern(domain, pattern string) bool {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	if pattern == "" || domain == "" {
		return false
	}
	if strings.Contains(pattern, "/") {
		_, ipNet, err := net.ParseCIDR(pattern)
		if err == nil {
			if ip := net.ParseIP(domain); ip != nil {
				return ipNet.Contains(ip)
			}
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		pattern = pattern[2:]
	} else if strings.HasPrefix(pattern, ".") {
		pattern = pattern[1:]
	}
	return domain == pattern || strings.HasSuffix(domain, "."+pattern)
}

func needsDomainSniff(destAddr string) bool {
	host, _, err := net.SplitHostPort(destAddr)
	if err != nil || net.ParseIP(host) == nil {
		return false // FakeDNS already supplied an unambiguous domain.
	}
	routeMu.RLock()
	defer routeMu.RUnlock()
	return (routeMode == "bypass" && len(directDomains) > 0) ||
		((routeMode == "rules" || routeMode == "proxy") && len(proxyDomains) > 0)
}

func matchDomainList(target string, patterns []string) bool {
	if target == "" || len(patterns) == 0 {
		return false
	}
	for _, pat := range patterns {
		if matchDomainPattern(target, pat) {
			return true
		}
	}
	return false
}

func matchTargetAgainstPatterns(destAddr string, peekData []byte, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		host = destAddr
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// A CDN address is not a domain identity. A cached name must never grant
	// direct access to a different connection sharing that address.
	if matchDomainList(host, patterns) {
		return true
	}
	if name := routepeek.ServerName(peekData); name != "" {
		return matchDomainList(name, patterns)
	}
	if name := routepeek.HTTPHost(peekData); name != "" {
		return matchDomainList(name, patterns)
	}
	return false
}

// ShouldRouteTarget decides whether this destination should go through VPN.
func ShouldRouteTarget(destAddr string, peekData []byte) bool {
	routeMu.RLock()
	mode := routeMode
	pDoms := proxyDomains
	dDoms := directDomains
	routeMu.RUnlock()

	// Mode 1: ALL (Global VPN)
	if mode == "" || mode == "all" {
		return true // Route via VPN
	}

	// Mode 2: RULES / PROXY (Only proxy selected domains)
	if mode == "rules" || mode == "proxy" {
		if len(pDoms) > 0 && matchTargetAgainstPatterns(destAddr, peekData, pDoms) {
			return true // In proxy list -> route via VPN
		}
		if len(pDoms) > 0 {
			host, _, err := net.SplitHostPort(destAddr)
			if err != nil {
				host = destAddr
			}
			if net.ParseIP(host) != nil && routepeek.ServerName(peekData) == "" && routepeek.HTTPHost(peekData) == "" {
				return true // Unknown/partial/ECH: keep traffic protected.
			}
		}
		return false
	}

	// Mode 3: BYPASS (Direct access for selected domains, everything else via VPN)
	if mode == "bypass" {
		if len(dDoms) > 0 && matchTargetAgainstPatterns(destAddr, peekData, dDoms) {
			return false // In direct list -> Direct bypass
		}
		return true // Route via VPN
	}

	return true
}

func isDirect(destAddr string, peekData []byte) bool {
	return !ShouldRouteTarget(destAddr, peekData)
}

func learnDNSResponse(data []byte) {
	if len(data) < 12 {
		return
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return
	}
	qdCount := int(binary.BigEndian.Uint16(data[4:6]))
	anCount := int(binary.BigEndian.Uint16(data[6:8]))
	if anCount == 0 {
		return
	}

	offset := 12
	var questionDomain string
	for i := 0; i < qdCount && offset < len(data); i++ {
		var domainParts []string
		for offset < len(data) {
			l := int(data[offset])
			offset++
			if l == 0 {
				break
			}
			if offset+l > len(data) {
				return
			}
			domainParts = append(domainParts, string(data[offset:offset+l]))
			offset += l
		}
		offset += 4
		if i == 0 {
			questionDomain = strings.ToLower(strings.Join(domainParts, "."))
		}
	}

	if questionDomain == "" {
		return
	}

	for i := 0; i < anCount && offset < len(data); i++ {
		if offset >= len(data) {
			break
		}
		if data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) {
				l := int(data[offset])
				offset++
				if l == 0 {
					break
				}
				offset += l
			}
		}
		if offset+10 > len(data) {
			break
		}
		aType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(data) {
			break
		}
		if aType == 1 && rdLen == 4 {
			ip := net.IP(data[offset : offset+4]).String()
			ipToDomain.Store(ip, questionDomain)
		}
		offset += rdLen
	}
}

// SocketProtector allows protecting sockets created by the Go runtime from being captured by VpnService.
type SocketProtector interface {
	Protect(fd int) bool
}

var (
	protectorMu sync.RWMutex
	protector   SocketProtector
)

// SetSocketProtector registers the Android VpnService protector instance.
func SetSocketProtector(p SocketProtector) {
	protectorMu.Lock()
	defer protectorMu.Unlock()
	protector = p
}

func protectSocket(fd int) error {
	protectorMu.RLock()
	p := protector
	protectorMu.RUnlock()
	if p == nil {
		return fmt.Errorf("Android socket protector is not registered")
	}
	if !p.Protect(fd) {
		return fmt.Errorf("VpnService.protect(%d) failed", fd)
	}
	return nil
}

var directDNSList = []string{"77.88.8.8:53", "1.1.1.1:53", "8.8.8.8:53"}

func resolveDirectDomain(domain string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, dnsAddr := range directDNSList {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{
					Timeout: 1200 * time.Millisecond,
					Control: func(network, address string, c syscall.RawConn) error {
						var protectErr error
						if err := c.Control(func(fd uintptr) { protectErr = protectSocket(int(fd)) }); err != nil {
							return err
						}
						return protectErr
					},
				}
				return d.DialContext(dialCtx, "udp", dnsAddr)
			},
		}
		ips, err := resolver.LookupIP(ctx, "ip4", domain)
		if err == nil && len(ips) > 0 {
			return ips[0].String()
		}
	}
	return ""
}

func dialDirect(network, address string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	targetAddr := address
	if err == nil {
		if net.ParseIP(host) == nil {
			// Domain: resolve via direct protected DNS outside of VPN TUN
			if ip := resolveDirectDomain(host); ip != "" {
				targetAddr = net.JoinHostPort(ip, port)
			}
		}
	}

	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			if err := c.Control(func(fd uintptr) { protectErr = protectSocket(int(fd)) }); err != nil {
				return err
			}
			return protectErr
		},
	}
	return d.Dial(network, targetAddr)
}

func sniffSNI(data []byte) string {
	if len(data) < 9 || data[0] != 0x16 {
		return ""
	}
	// Note: recLen is the full TLS record length. In modern TLS (Chrome with Kyber/ML-KEM post-quantum keys),
	// the ClientHello can be ~1800+ bytes, which exceeds a single MTU segment (1360 bytes).
	// However, the SNI extension is located at the beginning of the extensions block (bytes 150-300),
	// which is ALWAYS present in the first TCP segment!
	// Therefore, we must NOT require len(data) >= 5 + recLen. We parse available bytes!
	payload := data[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return ""
	}
	sessionIDLenOffset := 38
	if len(payload) <= sessionIDLenOffset {
		return ""
	}
	sessionIDLen := int(payload[sessionIDLenOffset])
	cipherOffset := sessionIDLenOffset + 1 + sessionIDLen
	if len(payload) <= cipherOffset+2 {
		return ""
	}
	cipherLen := int(binary.BigEndian.Uint16(payload[cipherOffset : cipherOffset+2]))
	compOffset := cipherOffset + 2 + cipherLen
	if len(payload) <= compOffset+1 {
		return ""
	}
	compLen := int(payload[compOffset])
	extOffset := compOffset + 1 + compLen
	if len(payload) <= extOffset+2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(payload[extOffset : extOffset+2]))
	extData := payload[extOffset+2:]
	if len(extData) > extLen {
		extData = extData[:extLen]
	}
	idx := 0
	for idx+4 <= len(extData) {
		eType := binary.BigEndian.Uint16(extData[idx : idx+2])
		eLen := int(binary.BigEndian.Uint16(extData[idx+2 : idx+4]))
		idx += 4
		if idx+eLen > len(extData) {
			break
		}
		if eType == 0x0000 {
			snData := extData[idx : idx+eLen]
			if len(snData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(snData[3:5]))
				if len(snData) >= 5+nameLen {
					return string(snData[5 : 5+nameLen])
				}
			}
		}
		idx += eLen
	}
	return ""
}

func sniffHTTPHost(data []byte) string {
	s := string(data)
	idx := strings.Index(strings.ToLower(s), "\nhost:")
	if idx == -1 {
		idx = strings.Index(strings.ToLower(s), "\r\nhost:")
		if idx == -1 {
			return ""
		}
		idx += 2
	} else {
		idx += 1
	}
	line := s[idx+5:]
	end := strings.IndexAny(line, "\r\n")
	if end != -1 {
		line = line[:end]
	}
	host := strings.TrimSpace(line)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
