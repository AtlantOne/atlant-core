package main

import (
	"atlant.local/protocol/routepeek"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/armon/go-socks5"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Runtime DLLs live beside the executable, not among Go sources.
func ensureWintunDLL() error {
	ex, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate core executable: %w", err)
	}
	dll, err := wintunDLLPath(ex)
	if err != nil {
		return err
	}
	return windows.SetDllDirectory(filepath.Dir(dll))
}

// TUN implementation

const (
	// defaultMTU for TUN interface (optimal for WireGuard / Reality / QUIC Datagrams: fits in 1500 Ethernet MTU)
	defaultMTU = 1360
)

// linkEndpoint wraps tun.Device to bridge system stack and gVisor stack.
type linkEndpoint struct {
	tun        tun.Device
	dispatcher stack.NetworkDispatcher
	mtu        uint32
}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// Read packets from TUN device and deliver to gVisor
	go func() {
		bufSize := 2048
		if int(e.mtu) > 1900 {
			bufSize = int(e.mtu) + 128
		}
		data := make([]byte, bufSize)
		buffs := [][]byte{data}
		sizes := []int{0}
		for {
			n, err := e.tun.Read(buffs, sizes, 0)
			if err != nil {
				log.Printf("[TUN] Read error: %v", err)
				return
			}
			if n == 0 || sizes[0] == 0 {
				continue
			}

			// Filter IPv4 packets
			var p tcpip.NetworkProtocolNumber
			switch header.IPVersion(data[:sizes[0]]) {
			case 4:
				p = header.IPv4ProtocolNumber
			default:
				continue
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data[:sizes[0]]),
			})
			e.dispatcher.DeliverNetworkPacket(p, pkt)
			pkt.DecRef()
		}
	}()
}

func (e *linkEndpoint) IsAttached() bool { return e.dispatcher != nil }
func (e *linkEndpoint) MTU() uint32 {
	if e.mtu > 0 {
		return e.mtu
	}
	return defaultMTU
}
func (e *linkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (e *linkEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *linkEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *linkEndpoint) Wait()                                        {}
func (e *linkEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *linkEndpoint) Close()                                       {}
func (e *linkEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *linkEndpoint) SetOnCloseAction(func())                      {}
func (e *linkEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *linkEndpoint) SetMTU(uint32)                                {}
func (e *linkEndpoint) AddHeader(pkt *stack.PacketBuffer) {
}

func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		_, err := e.tun.Write([][]byte{view.AsSlice()}, 0)
		view.Release()
		if err != nil {
			log.Printf("[TUN] Write error: %v", err)
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func startTun(cfg *Config) {
	if err := ensureWintunDLL(); err != nil {
		log.Fatalf("[TUN] %v", err)
	}
	log.Println("[TUN] Starting TUN mode (requires Administrator privileges).")

	// Avoid routing loop by resolving server IP before route setup
	host, port, _ := net.SplitHostPort(cfg.ServerAddr)
	if host == "" {
		host = cfg.ServerAddr
	}
	var allServerIPs []net.IP
	ips, err := net.LookupIP(host)
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				allServerIPs = append(allServerIPs, ip4)
			}
		}
		if len(allServerIPs) > 0 && port != "" {
			cfg.ServerAddr = net.JoinHostPort(allServerIPs[0].String(), port)
			log.Printf("[TUN] Fixed server IP: %s", cfg.ServerAddr)
		}
	}
	for _, bkp := range cfg.BackupServers {
		bHost, _, bErr := net.SplitHostPort(bkp)
		if bErr != nil {
			bHost = bkp
		}
		if bIPs, err := net.LookupIP(bHost); err == nil {
			for _, bip := range bIPs {
				if ip4 := bip.To4(); ip4 != nil {
					allServerIPs = append(allServerIPs, ip4)
				}
			}
		}
	}

	// Create TUN device
	effectiveMTU := cfg.MTU
	if effectiveMTU <= 0 {
		effectiveMTU = defaultMTU
	}
	log.Printf("[TUN] Initializing Wintun adapter '%s' with MTU %d", cfg.TunName, effectiveMTU)
	tunDevice, err := tun.CreateTUN(cfg.TunName, effectiveMTU)
	if err != nil {
		log.Fatalf("[TUN] Failed to create TUN device: %v", err)
	}
	defer tunDevice.Close()

	// Give Windows time to register the new wintun adapter before netsh can configure it
	time.Sleep(900 * time.Millisecond)

	// Configure network interface (retry once if Windows isn't ready yet)
	if err := configureInterface(cfg); err != nil {
		log.Printf("[TUN] configureInterface failed (%v), retrying in 1s...", err)
		time.Sleep(1 * time.Second)
		if err2 := configureInterface(cfg); err2 != nil {
			log.Fatalf("[TUN] configureInterface retry failed: %v", err2)
		}
	}

	// Configure system routes
	if err := configureRoutes(cfg, allServerIPs); err != nil {
		cleanupRoutes(cfg)
		log.Fatalf("[TUN] Failed to configure routes: %v", err)
	}

	stopOnce := sync.Once{}
	doGracefulExit := func(reason string) {
		stopOnce.Do(func() {
			log.Printf("[TUN] Shutdown triggered (%s), cleaning up routes and adapter...", reason)
			cleanupRoutes(cfg)
			if tunDevice != nil {
				_ = tunDevice.Close()
			}
			os.Exit(0)
		})
	}

	const sigBrk = syscall.Signal(0x15) // CTRL_BREAK_EVENT
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, sigBrk)
	go func() {
		sig := <-c
		doGracefulExit(fmt.Sprintf("signal %v", sig))
	}()

	go func() {
		buf := make([]byte, 512)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				// Stdin closed or running without console/under UAC. Do NOT abort VPN.
				return
			}
			if n > 0 && strings.Contains(string(buf[:n]), "STOP") {
				doGracefulExit("stdin command")
				return
			}
		}
	}()

	cleanupDone := false
	defer func() {
		if !cleanupDone {
			cleanupRoutes(cfg)
		}
	}()

	// Create gVisor stack
	s, err := createStack()
	if err != nil {
		log.Fatalf("[TUN] Failed to create gVisor stack: %v", err)
	}

	// Attach NIC
	linkEP := &linkEndpoint{tun: tunDevice, mtu: uint32(effectiveMTU)}
	if err := s.CreateNIC(1, linkEP); err != nil {
		log.Fatalf("[TUN] Failed to create NIC: %v", err)
	}

	if err := s.SetPromiscuousMode(1, true); err != nil {
		log.Fatalf("[TUN] Failed to enable Promiscuous mode: %v", err)
	}

	if err := s.SetSpoofing(1, true); err != nil {
		log.Fatalf("[TUN] Failed to enable Spoofing: %v", err)
	}

	// Assign IP and default route
	prefixLen := 24
	if maskIP := net.ParseIP(cfg.TunMask); maskIP != nil {
		if mask := net.IPMask(maskIP.To4()); mask != nil {
			if ones, _ := mask.Size(); ones > 0 {
				prefixLen = ones
			}
		}
	}

	addr, _ := netip.ParseAddr(cfg.TunAddr)
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: prefixLen,
		},
	}
	if err := s.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		log.Fatalf("[TUN] Failed to add protocol address: %v", err)
	}

	// Добавляем также адрес шлюза в стек gVisor для корректного ARP/маршрутизации
	if gwAddr, err := netip.ParseAddr(cfg.TunGw); err == nil {
		gwProto := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(gwAddr.AsSlice()),
				PrefixLen: prefixLen,
			},
		}
		_ = s.AddProtocolAddress(1, gwProto, stack.AddressProperties{})
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
	})

	// Handlers for TCP and UDP (2MB receive window for unthrottled gigabit upload)
	tcpForwarder := tcp.NewForwarder(s, 2*1024*1024, 65535, func(r *tcp.ForwarderRequest) {
		go handleTCP(r, cfg)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		destAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))

		// Filter NetBIOS and mDNS noise
		if id.LocalPort == 137 || id.LocalPort == 138 || id.LocalPort == 5353 {
			return false
		}

		// Reject QUIC (UDP 443) only in full tunnel TCP mode unless Telegram Voice/RTC
		if id.LocalPort == 443 && cfg.RouteMode == "all" && strings.ToLower(cfg.TrafficMode) != "udp" && !isTelegramIP(id.LocalAddress.String()) {
			return false
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("[UDP] Failed to create endpoint: %v", err)
			return false
		}

		go handleUDP(ep, &wq, cfg, destAddr, id.RemotePort)
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	log.Println("[TUN] VPN started. Full system routing active.")
	select {}
}

func isTelegramIP(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// Telegram IP blocks (AS44907, AS62041, AS62014, AS59930)
	if (ip4[0] == 91 && ip4[1] == 108) ||
		(ip4[0] == 149 && ip4[1] == 154) ||
		(ip4[0] == 185 && ip4[1] == 76 && ip4[2] == 151) {
		return true
	}
	return false
}

func matchDomainPattern(domain, pattern string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
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

var directResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		if physicalLocalIP != nil {
			d.LocalAddr = &net.UDPAddr{IP: physicalLocalIP}
		}
		ensureDirectRoute("8.8.8.8")
		return d.DialContext(ctx, "udp", "8.8.8.8:53")
	},
}

func resolveDirectIPs(host string) ([]net.IP, error) {
	if GetFakeDNS().IsFakeIPStr(host) {
		if dom, ok := GetFakeDNS().LookupDomain(host); ok {
			host = dom
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return directResolver.LookupIP(ctx, "ip4", host)
}

func dialDirectTCP(destAddr string, cfg *Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(destAddr)
	targetAddr := destAddr
	if err == nil {
		if cfg.FakeDNS && GetFakeDNS().IsFakeIPStr(host) {
			if dom, ok := GetFakeDNS().LookupDomain(host); ok {
				host = dom
			}
		}
		if ip := net.ParseIP(host); ip != nil {
			ensureDirectRoute(ip.String())
		} else {
			// Domain: resolve via direct upstream resolver and add host bypass route
			if ips, err := resolveDirectIPs(host); err == nil && len(ips) > 0 {
				for _, rip := range ips {
					if ip4 := rip.To4(); ip4 != nil {
						ensureDirectRoute(ip4.String())
						targetAddr = net.JoinHostPort(ip4.String(), port)
						break
					}
				}
			}
		}
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	if physicalLocalIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: physicalLocalIP}
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil && dialer.LocalAddr != nil {
		dialer.LocalAddr = nil
		return dialer.Dial("tcp", targetAddr)
	}
	return conn, err
}

func dialDirectUDP(destAddr string, cfg *Config) (*net.UDPConn, error) {
	host, port, err := net.SplitHostPort(destAddr)
	targetAddr := destAddr
	if err == nil {
		if cfg.FakeDNS && GetFakeDNS().IsFakeIPStr(host) {
			if dom, ok := GetFakeDNS().LookupDomain(host); ok {
				host = dom
			}
		}
		if ip := net.ParseIP(host); ip != nil {
			ensureDirectRoute(ip.String())
		} else {
			if ips, err := resolveDirectIPs(host); err == nil && len(ips) > 0 {
				for _, rip := range ips {
					if ip4 := rip.To4(); ip4 != nil {
						ensureDirectRoute(ip4.String())
						targetAddr = net.JoinHostPort(ip4.String(), port)
						break
					}
				}
			}
		}
	}
	rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return nil, err
	}
	var lAddr *net.UDPAddr
	if physicalLocalIP != nil {
		lAddr = &net.UDPAddr{IP: physicalLocalIP}
	}
	conn, err := net.DialUDP("udp", lAddr, rAddr)
	if err != nil && lAddr != nil {
		return net.DialUDP("udp", nil, rAddr)
	}
	return conn, err
}

var (
	ipToDomain      sync.Map
	ipToDomainCount atomic.Int64
)

func storeIPToDomain(ip, domain string) {
	if ip == "" || domain == "" {
		return
	}
	if ipToDomainCount.Load() > 10000 {
		count := 0
		ipToDomain.Range(func(key, val any) bool {
			ipToDomain.Delete(key)
			ipToDomainCount.Add(-1)
			count++
			return count < 5000
		})
	}
	if _, loaded := ipToDomain.LoadOrStore(ip, domain); !loaded {
		ipToDomainCount.Add(1)
	}
}

func parseDNSName(data []byte, offset int) (int, string) {
	var parts []string
	curr := offset
	jumped := false
	nextOffset := -1
	loops := 0

	for curr < len(data) && loops < 20 {
		loops++
		if data[curr] == 0 {
			if !jumped {
				nextOffset = curr + 1
			}
			break
		}
		if data[curr]&0xC0 == 0xC0 {
			if curr+1 >= len(data) {
				return -1, ""
			}
			ptr := int(binary.BigEndian.Uint16(data[curr:curr+2]) & 0x3FFF)
			if !jumped {
				nextOffset = curr + 2
				jumped = true
			}
			curr = ptr
			continue
		}
		l := int(data[curr])
		curr++
		if curr+l > len(data) {
			return -1, ""
		}
		parts = append(parts, string(data[curr:curr+l]))
		curr += l
	}

	if !jumped {
		nextOffset = curr
	}
	return nextOffset, strings.Join(parts, ".")
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
		next, name := parseDNSName(data, offset)
		if next < 0 || next+4 > len(data) {
			return
		}
		if i == 0 {
			questionDomain = strings.ToLower(name)
		}
		offset = next + 4
	}

	if questionDomain == "" {
		return
	}

	for i := 0; i < anCount && offset < len(data); i++ {
		next, _ := parseDNSName(data, offset)
		if next < 0 || next+10 > len(data) {
			break
		}
		offset = next
		aType := binary.BigEndian.Uint16(data[offset : offset+2])
		rdLen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10
		if offset+rdLen > len(data) {
			break
		}
		if aType == 1 && rdLen == 4 {
			ip := net.IP(data[offset : offset+4]).String()
			storeIPToDomain(ip, questionDomain)
		}
		offset += rdLen
	}
}

func sniffSNI(data []byte) string {
	if len(data) < 9 || data[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	payloadLen := recLen
	if len(data)-5 < payloadLen {
		payloadLen = len(data) - 5
	}
	if payloadLen < 4 {
		return ""
	}
	payload := data[5 : 5+payloadLen]
	if payload[0] != 0x01 {
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

type bufferedConn struct {
	net.Conn
	buf []byte
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	if len(b.buf) > 0 {
		n := copy(p, b.buf)
		b.buf = b.buf[n:]
		return n, nil
	}
	return b.Conn.Read(p)
}

func shouldRoute(clientPort uint16, isUDP bool, destAddr string, cfg *Config, observedNames ...string) bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.RouteMode))
	if mode == "" || mode == "all" {
		return true // Все соединения через туннель
	}

	procName := GetProcessNameForPort(clientPort, isUDP)

	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		host = destAddr
	}
	host = strings.ToLower(strings.TrimSpace(host))

	domainToMatch := host
	observedName := ""
	if len(observedNames) > 0 {
		observedName = observedNames[0]
	}
	if observedName != "" {
		domainToMatch = observedName
	} else if val, ok := ipToDomain.Load(host); ok && (mode == "rules" || mode == "proxy_apps") {
		domainToMatch = val.(string)
	}

	// Режим: только по правилам / проксировать
	if mode == "rules" || mode == "proxy_apps" {
		if matchProcess(procName, cfg.ProxyApps) {
			return true
		}
		for _, pat := range cfg.ProxyDomains {
			if matchDomainPattern(domainToMatch, pat) || matchDomainPattern(host, pat) {
				return true
			}
		}
		if len(cfg.ProxyDomains) > 0 && net.ParseIP(host) != nil && observedName == "" {
			return true // Unknown, partial or ECH name: keep traffic protected.
		}
		return false
	}

	// Режим: исключения (прямой доступ для совпадений)
	if mode == "bypass" || mode == "bypass_apps" {
		if matchProcess(procName, cfg.BypassApps) {
			return false
		}
		for _, pat := range cfg.DirectDomains {
			if matchDomainPattern(domainToMatch, pat) || matchDomainPattern(host, pat) {
				return false
			}
		}
		return true
	}

	return true
}

func isServerAddress(destAddr string, cfg *Config) bool {
	destHost, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		destHost = destAddr
	}
	serverHost, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		serverHost = cfg.ServerAddr
	}
	if strings.EqualFold(destHost, serverHost) {
		return true
	}
	for _, backup := range cfg.BackupServers {
		bHost, _, err := net.SplitHostPort(backup)
		if err == nil && strings.EqualFold(destHost, bHost) {
			return true
		}
	}
	return false
}

func handleTCP(r *tcp.ForwarderRequest, cfg *Config) {
	reqID := r.ID()
	destAddr := net.JoinHostPort(reqID.LocalAddress.String(), strconv.Itoa(int(reqID.LocalPort)))

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("[TCP] Failed to create endpoint for %s: %v", destAddr, tcpErr)
		r.Complete(true)
		return
	}
	r.Complete(false)

	gvisorConn := gonet.NewTCPConn(&wq, ep)
	defer gvisorConn.Close()

	host, port, _ := net.SplitHostPort(destAddr)
	if cfg.FakeDNS && GetFakeDNS().IsFakeIPStr(host) {
		if dom, ok := GetFakeDNS().LookupDomain(host); ok {
			destAddr = fmt.Sprintf("%s:%s", dom, port)
		}
	}

	var clientConn net.Conn = gvisorConn
	observedName := ""
	if cfg.RouteMode != "all" {
		portNum := reqID.LocalPort
		// Skip peeking for server-first protocols (SSH 22, SMTP 25, FTP 21, POP3 110, IMAP 143)
		if portNum != 22 && portNum != 25 && portNum != 21 && portNum != 110 && portNum != 143 {
			peekBuf := routepeek.Read(gvisorConn, 400*time.Millisecond)
			if len(peekBuf) > 0 {
				clientConn = &bufferedConn{Conn: gvisorConn, buf: peekBuf}
				observedName = routepeek.ServerName(peekBuf)
				if observedName == "" {
					observedName = routepeek.HTTPHost(peekBuf)
				}
			}
		}
	}

	// Routing loop prevention: server traffic must NEVER be looped back into VPN
	if isServerAddress(destAddr, cfg) || !shouldRoute(uint16(reqID.RemotePort), false, destAddr, cfg, observedName) {
		directConn, err := dialDirectTCP(destAddr, cfg)
		if err != nil {
			log.Printf("[TCP-DIRECT] Direct dial error to %s: %v", destAddr, err)
			return
		}
		defer directConn.Close()

		var wg sync.WaitGroup
		var once sync.Once
		wg.Add(2)
		closeBoth := func() {
			_ = clientConn.Close()
			_ = directConn.Close()
		}
		relay := func(dst, src net.Conn) {
			defer wg.Done()
			defer once.Do(closeBoth)
			buf := make([]byte, 64*1024)
			io.CopyBuffer(dst, src, buf)
		}
		go relay(directConn, clientConn)
		go relay(clientConn, directConn)
		wg.Wait()
		return
	}

	// Dial via VPN tunnel
	var remoteConn net.Conn
	var err error
	tcpProto := strings.ToLower(cfg.TCPProto)
	if strings.ToLower(cfg.TrafficMode) == "tcp" {
		if tcpProto == "xhttp" {
			remoteConn, err = dialXHTTPStream(cfg, "tcp", destAddr)
		} else {
			remoteConn, err = dialRemoteRealityStream(cfg, "tcp", destAddr)
		}
	} else {
		if tcpProto == "xhttp" {
			remoteConn, err = dialXHTTPStream(cfg, "tcp", destAddr)
		} else if tcpProto == "reality" {
			remoteConn, err = dialRemoteRealityStream(cfg, "tcp", destAddr)
		} else {
			remoteConn, err = dialAndWriteHeader(cfg, "tcp", destAddr)
		}
	}
	if err != nil {
		log.Printf("[TCP] Failed to connect to VPN for %s: %v", destAddr, err)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	var closeOnce sync.Once
	wg.Add(2)

	closeBoth := func() {
		_ = clientConn.Close()
		_ = remoteConn.Close()
	}

	// Upload: clientConn -> remoteConn
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, err := io.CopyBuffer(remoteConn, clientConn, buf)
		if err != nil {
			closeOnce.Do(closeBoth)
			return
		}
		// Client completed HTTP request (sent FIN). Forward CloseWrite to remoteConn if supported,
		// but KEEP remoteConn open so the download goroutine can finish reading the complete response!
		if cw, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Download: remoteConn -> clientConn
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(clientConn, remoteConn, buf)
		closeOnce.Do(closeBoth)
	}()

	wg.Wait()
	closeOnce.Do(closeBoth)
}

func handleUDP(ep tcpip.Endpoint, wq *waiter.Queue, cfg *Config, destAddr string, clientPort uint16) {
	gvisorConn := gonet.NewUDPConn(wq, ep)
	defer gvisorConn.Close()

	var firstPkt []byte

	// DNS queries (port 53)
	if strings.HasSuffix(destAddr, ":53") && cfg.FakeDNS {
		buf := make([]byte, 2048)
		_ = gvisorConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := gvisorConn.Read(buf)
		if err == nil && n > 0 {
			log.Printf("[DEBUG] [DNS] TUN query received: bytes=%d", n)
			qDomain, _, _, qErr := ParseQuestionDomain(buf[:n])
			routeTarget := destAddr
			if qErr == nil && qDomain != "" {
				routeTarget = qDomain + ":53"
			}
			if shouldRoute(clientPort, true, routeTarget, cfg) {
				if resp, ok := GetFakeDNS().HandleDNSQuery(buf[:n]); ok {
					_ = gvisorConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					if written, err := gvisorConn.Write(resp); err != nil || written != len(resp) {
						log.Printf("[ERROR] [DNS] Failed to deliver synthetic response: bytes=%d/%d err=%v", written, len(resp), err)
					} else {
						log.Printf("[DEBUG] [DNS] TUN response written: bytes=%d", written)
					}
					return // Instant 0.1ms resolution
				}
			}
			firstPkt = make([]byte, n)
			copy(firstPkt, buf[:n])
		}
	}

	h, p, _ := net.SplitHostPort(destAddr)
	if cfg.FakeDNS && GetFakeDNS().IsFakeIPStr(h) {
		if dom, ok := GetFakeDNS().LookupDomain(h); ok {
			destAddr = fmt.Sprintf("%s:%s", dom, p)
		}
	}

	// Routing loop prevention: server traffic must NEVER be looped back into VPN
	if isServerAddress(destAddr, cfg) || !shouldRoute(clientPort, true, destAddr, cfg) {
		directConn, err := dialDirectUDP(destAddr, cfg)
		if err != nil {
			log.Printf("[UDP-DIRECT] Failed to dial %s: %v", destAddr, err)
			return
		}
		defer directConn.Close()

		if len(firstPkt) > 0 {
			_, _ = directConn.Write(firstPkt)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer directConn.Close()
			buf := make([]byte, 65535)
			for {
				n, err := gvisorConn.Read(buf)
				if err != nil {
					return
				}
				directConn.Write(buf[:n])
			}
		}()
		go func() {
			defer wg.Done()
			defer gvisorConn.Close()
			buf := make([]byte, 65535)
			for {
				directConn.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, err := directConn.Read(buf)
				if err != nil {
					return
				}
				if strings.HasSuffix(destAddr, ":53") {
					learnDNSResponse(buf[:n])
				}
				gvisorConn.Write(buf[:n])
			}
		}()
		wg.Wait()
		return
	}

	// DNS запросы (порт 53) изолированно направляем через надежный стрим-туннель:
	// это исключает потерю пакетов и расхождение Transaction ID при пачке параллельных запросов
	if strings.HasSuffix(destAddr, ":53") {
		routeUDPViaTCP(gvisorConn, cfg, destAddr, firstPkt)
		return
	}

	// Блокировка QUIC (UDP 443) для форсирования надежного HTTP/2 только в режиме TCP/full tunnel
	if strings.HasSuffix(destAddr, ":443") && cfg.RouteMode == "all" && strings.ToLower(cfg.TrafficMode) != "udp" && !isTelegramIP(destAddr) {
		return
	}

	tMode := strings.ToLower(cfg.TrafficMode)

	switch tMode {
	case "udp":
		// Force QUIC UDP regardless of blocked state
		ok := handleUDPViaDatagramTunnel(gvisorConn, cfg, destAddr)
		if !ok {
			log.Printf("[UDP-FORCED] QUIC UDP failed for %s, connection dropped (forced UDP mode)", destAddr)
		}
		return
	case "tcp":
		// Force TCP tunnel — route UDP over TCP stream without QUIC fallback
		routeUDPViaTCP(gvisorConn, cfg, destAddr, nil)
		return
	default: // "split" or ""
		udpProto := strings.ToLower(cfg.UDPProto)
		if udpProto == "tcp" {
			routeUDPViaTCP(gvisorConn, cfg, destAddr, nil)
			return
		}
		if (udpProto == "quic" || udpProto == "" || strings.ToLower(cfg.Transport) == "quic") && !isUDPBlocked() {
			ok := handleUDPViaDatagramTunnel(gvisorConn, cfg, destAddr)
			if ok {
				return
			}
			log.Printf("[UDP-FAILOVER] UDP blocked to %s, fallback to TCP tunnel", destAddr)
			setUDPBlocked(true)
			startUDPRecoveryProbe(cfg)
			return
		}
		routeUDPViaTCP(gvisorConn, cfg, destAddr, nil)
	}
}

func dialAndWriteHeader(cfg *Config, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err == nil && cfg.FakeDNS && GetFakeDNS() != nil && GetFakeDNS().IsFakeIPStr(host) {
		if dom, ok := GetFakeDNS().LookupDomain(host); ok {
			addr = net.JoinHostPort(dom, port)
		}
	}
	if strings.ToLower(cfg.Transport) == "quic" {
		return dialQUICStream(cfg, network, addr)
	}
	if strings.ToLower(cfg.Transport) == "xhttp" {
		return dialXHTTPStream(cfg, network, addr)
	}
	return dialRemoteRealityStream(cfg, network, addr)
}

func createStack() (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	// Enable SACK to prevent throughput collapse upon packet drop
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Enable dynamic receive buffer scaling
	bufOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &bufOpt)

	// Set Cubic congestion control
	ccOpt := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

	return s, nil
}

// remoteResolver skips local DNS resolution entirely so the remote server resolves domain names
type remoteResolver struct{}

func (r remoteResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, net.IPv4zero, nil
}

// remoteRewriter restores the domain name so Dial receives the FQDN instead of a dummy IP
type remoteRewriter struct{}

func (r remoteRewriter) Rewrite(ctx context.Context, req *socks5.Request) (context.Context, *socks5.AddrSpec) {
	if req.DestAddr.FQDN != "" {
		return ctx, &socks5.AddrSpec{
			FQDN: req.DestAddr.FQDN,
			Port: req.DestAddr.Port,
		}
	}
	return ctx, req.DestAddr
}
