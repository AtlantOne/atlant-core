package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

var runLinuxNFT = func(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables protection unavailable: %w: %s", err, out)
	}
	return nil
}

func prepareTunEndpoints(cfg *Config) (*Config, error) {
	copyConfig := *cfg
	resolve := func(endpoint string) (string, error) {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return "", err
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return "", err
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return net.JoinHostPort(v4.String(), port), nil
			}
		}
		for _, ip := range ips {
			if ip.To16() != nil {
				return net.JoinHostPort(ip.String(), port), nil
			}
		}
		return "", fmt.Errorf("no usable IP address for VPN endpoint")
	}
	var err error
	copyConfig.ServerAddr, err = resolve(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve VPN endpoint before DNS isolation: %w", err)
	}
	copyConfig.BackupServers = make([]string, 0, len(cfg.BackupServers))
	for _, endpoint := range cfg.BackupServers {
		resolved, err := resolve(endpoint)
		if err != nil {
			return nil, fmt.Errorf("resolve backup endpoint: %w", err)
		}
		copyConfig.BackupServers = append(copyConfig.BackupServers, resolved)
	}
	return &copyConfig, nil
}

func linuxGuardScript(table, tunName, dns string, ipv6DNS ...string) (string, error) {
	return linuxGuardScriptForEndpoints(table, tunName, dns, nil, ipv6DNS...)
}

func linuxGuardScriptForEndpoints(table, tunName, dns string, endpoints []string, ipv6DNS ...string) (string, error) {
	ip := net.ParseIP(dns)
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "", fmt.Errorf("TUN DNS must be a public IPv4 address")
	}
	if len(tunName) == 0 || len(tunName) > 15 || strings.ContainsAny(tunName, "\x00\r\n") {
		return "", fmt.Errorf("invalid TUN interface name")
	}
	q := strconv.Quote(tunName)
	ipv6Guard := "add rule inet " + table + " guard meta nfproto ipv6 oifname != \"lo\" drop\n"
	ipv6NAT := ""
	endpointRules := ""
	hasIPv6Endpoint := false
	for _, endpoint := range endpoints {
		host, port, err := net.SplitHostPort(endpoint)
		address := net.ParseIP(host)
		number, portErr := strconv.Atoi(port)
		if err != nil || address == nil || portErr != nil || number < 1 || number > 65535 {
			return "", fmt.Errorf("invalid VPN endpoint for IPv6 guard")
		}
		if address.To4() != nil {
			continue
		}
		hasIPv6Endpoint = true
		for _, protocol := range []string{"tcp", "udp"} {
			endpointRules += "add rule inet " + table + " guard meta iif 0 ip6 daddr " + address.String() + " " + protocol + " dport " + strconv.Itoa(number) + " accept\n"
		}
	}
	if hasIPv6Endpoint {
		// An IPv6 outer connection still needs link-local neighbour discovery.
		// Only NDP control messages with the mandated hop limit bypass the guard.
		endpointRules += "add rule inet " + table + " guard meta iif 0 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { 133, 135, 136 } accept\n"
	}
	if len(ipv6DNS) > 0 {
		v6 := net.ParseIP(ipv6DNS[0])
		if v6 == nil || v6.To4() != nil || !v6.IsGlobalUnicast() || v6.IsPrivate() || v6.IsLoopback() || v6.IsLinkLocalUnicast() {
			return "", fmt.Errorf("IPv6 TUN DNS must be a public IPv6 address")
		}
		ipv6Guard = "add rule inet " + table + " guard meta nfproto ipv6 oifname != { \"lo\", " + q + " } drop\n"
		ipv6NAT = "add rule inet " + table + " dns ip6 daddr != ::1 udp dport 53 dnat ip6 to " + v6.String() + "\n" +
			"add rule inet " + table + " dns ip6 daddr != ::1 tcp dport 53 dnat ip6 to " + v6.String() + "\n"
	}
	return "add table inet " + table + "\n" +
		"add chain inet " + table + " dns { type nat hook output priority -100; policy accept; }\n" +
		"add rule inet " + table + " dns ip daddr != 127.0.0.0/8 udp dport 53 dnat ip to " + ip.To4().String() + "\n" +
		"add rule inet " + table + " dns ip daddr != 127.0.0.0/8 tcp dport 53 dnat ip to " + ip.To4().String() + "\n" +
		ipv6NAT +
		"add chain inet " + table + " guard { type filter hook postrouting priority 0; policy accept; }\n" +
		endpointRules + strings.Replace(ipv6Guard, " guard meta ", " guard meta iif 0 meta ", 1) +
		// OUTPUT still sees the old egress interface after DNAT. Check DNS at
		// POSTROUTING, after the kernel has recomputed the destination route.
		// iif 0 scopes this to locally originated traffic, not container forwarding.
		"add chain inet " + table + " dns_guard { type filter hook postrouting priority 0; policy accept; }\n" +
		"add rule inet " + table + " dns_guard meta iif 0 oifname != { \"lo\", " + q + " } udp dport 53 drop\n" +
		"add rule inet " + table + " dns_guard meta iif 0 oifname != { \"lo\", " + q + " } tcp dport 53 drop\n", nil
}

func installLinuxGuard(tunName, dns string, endpoints []string, ipv6DNS ...string) (string, error) {
	if dns == "" {
		dns = "1.1.1.1"
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	table := "atlant_" + hex.EncodeToString(random[:])
	script, err := linuxGuardScriptForEndpoints(table, tunName, dns, endpoints, ipv6DNS...)
	if err != nil {
		return "", err
	}
	// nft -f submits this as one transaction, not a partly installed rule set.
	if err := runLinuxNFT(script); err != nil {
		return "", err
	}
	return table, nil
}
