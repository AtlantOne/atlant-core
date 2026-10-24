package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const defaultMTU = 1380

type linkEndpoint struct {
	tun        tun.Device
	dispatcher stack.NetworkDispatcher
	closed     chan struct{}
	mtu        uint32
	closeOnce  sync.Once
}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	go func() {
		batchSize := e.tun.BatchSize()
		if batchSize <= 0 {
			batchSize = 128
		}
		buffs := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		for i := range buffs {
			buffs[i] = make([]byte, int(e.MTU())+tunWriteOffset)
		}

		for {
			select {
			case <-e.closed:
				return
			default:
			}

			n, err := e.tun.Read(buffs, sizes, 0)
			if err != nil {
				select {
				case <-e.closed:
					return
				default:
				}
				log.Printf("[TUN] Read error: %v", err)
				time.Sleep(10 * time.Millisecond)
				continue
			}

			for i := 0; i < n; i++ {
				packetSize := sizes[i]
				if packetSize <= 0 {
					continue
				}
				packetData := buffs[i][:packetSize]

				var p tcpip.NetworkProtocolNumber
				switch header.IPVersion(packetData) {
				case 4:
					p = header.IPv4ProtocolNumber
				case 6:
					p = header.IPv6ProtocolNumber
				default:
					continue
				}

				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(packetData),
				})
				e.dispatcher.DeliverNetworkPacket(p, pkt)
				pkt.DecRef()
			}
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
func (e *linkEndpoint) Close()                                       { e.closeOnce.Do(func() { close(e.closed) }) }
func (e *linkEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *linkEndpoint) SetOnCloseAction(func())                      {}
func (e *linkEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *linkEndpoint) SetMTU(uint32)                                {}
func (e *linkEndpoint) AddHeader(pkt *stack.PacketBuffer)            {}

func (e *linkEndpoint) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

const tunWriteOffset = 16

func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		slice := view.AsSlice()
		buf := make([]byte, tunWriteOffset+len(slice))
		copy(buf[tunWriteOffset:], slice)
		view.Release()
		_, err := e.tun.Write([][]byte{buf}, tunWriteOffset)
		if err != nil && !e.isClosed() {
			log.Printf("[TUN] Write error: %v", err)
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

type routeState struct {
	serverIPs []string
	origGW    string
	origDev   string
	tunDev    string
	undo      [][]string
	guard     string
}

var activeRoutes *routeState

func setupLinuxRouting(cfg *Config) (*routeState, error) {
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		host = cfg.ServerAddr
	}
	serverIPs, err := net.LookupIP(host)
	if err != nil || len(serverIPs) == 0 {
		return nil, fmt.Errorf("failed to resolve server host %s: %w", host, err)
	}
	serverIP := serverIPs[0].String()
	pinnedIPs := []string{serverIP}

	tunName := cfg.TunName
	if tunName == "" {
		tunName = "atlant0"
	}

	state := &routeState{serverIPs: pinnedIPs, tunDev: tunName}
	committed := false
	defer func() {
		if !committed {
			cleanupLinuxRouting(state)
		}
	}()
	add := func(family string, args ...string) error {
		if out, err := exec.Command("ip", append([]string{family, "route", "add"}, args...)...).CombinedOutput(); err != nil {
			return fmt.Errorf("install route: %w: %s", err, out)
		}
		state.undo = append(state.undo, append([]string{family, "route", "del"}, args...))
		return nil
	}
	seen := make(map[string]bool)
	pin := func(address string) error {
		if seen[address] {
			return nil
		}
		seen[address] = true
		family, prefix := "-4", "/32"
		if net.ParseIP(address).To4() == nil {
			family, prefix = "-6", "/128"
		}
		out, err := exec.Command("ip", family, "route", "get", address).CombinedOutput()
		if err != nil {
			return fmt.Errorf("route to VPN endpoint: %w: %s", err, out)
		}
		fields := strings.Fields(string(out))
		gateway, device := "", ""
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "via" {
				gateway = fields[i+1]
			}
			if fields[i] == "dev" {
				device = fields[i+1]
			}
		}
		if device == "" || device == tunName {
			return fmt.Errorf("no physical route for VPN endpoint")
		}
		// Local endpoints are used by isolated tests and loopback deployments.
		if len(fields) > 0 && fields[0] == "local" {
			return nil
		}
		args := []string{address + prefix}
		if gateway != "" {
			args = append(args, "via", gateway)
		}
		args = append(args, "dev", device)
		return add(family, args...)
	}
	if err := pin(serverIP); err != nil {
		return nil, err
	}
	for _, bkp := range cfg.BackupServers {
		bHost, _, bErr := net.SplitHostPort(bkp)
		if bErr == nil {
			if bIPs, err := net.LookupIP(bHost); err == nil && len(bIPs) > 0 {
				backupIP := bIPs[0].String()
				if backupIP == serverIP {
					continue
				}
				if err := pin(backupIP); err != nil {
					return nil, err
				}
				pinnedIPs = append(pinnedIPs, backupIP)
			}
		}
	}

	var dns6 []string
	if !cfg.DisableIPv6 {
		value := cfg.TunDNSIPv6
		if value == "" {
			value = "2606:4700:4700::1111"
		}
		dns6 = []string{value}
	}
	guard, err := installLinuxGuard(tunName, cfg.TunDNS, append([]string{cfg.ServerAddr}, cfg.BackupServers...), dns6...)
	if err != nil {
		return nil, err
	}
	state.guard = guard
	if err := add("-4", "0.0.0.0/1", "dev", tunName); err != nil {
		return nil, err
	}
	if err := add("-4", "128.0.0.0/1", "dev", tunName); err != nil {
		return nil, err
	}

	// Route FakeDNS pool via TUN
	if cfg.FakeDNS {
		if err := add("-4", "198.18.0.0/15", "dev", tunName); err != nil {
			return nil, err
		}
	}

	if !cfg.DisableIPv6 {
		for _, route := range []string{"::/1", "8000::/1"} {
			if err := add("-6", route, "dev", tunName); err != nil {
				return nil, err
			}
		}
	}
	log.Printf("[ROUTING] Default routes applied via %s; VPN endpoint %s bypasses TUN; IPv6=%t", tunName, serverIP, !cfg.DisableIPv6)

	committed = true
	return state, nil
}

func cleanupLinuxRouting(state *routeState) {
	if state == nil {
		return
	}
	log.Println("[ROUTING] Restoring original Linux routes...")
	for i := len(state.undo) - 1; i >= 0; i-- {
		if out, err := exec.Command("ip", state.undo[i]...).CombinedOutput(); err != nil {
			log.Printf("[ROUTING] Owned route cleanup failed: %v: %s", err, out)
		}
	}
	if state.guard != "" {
		if err := runLinuxNFT("delete table inet " + state.guard + "\n"); err != nil {
			log.Printf("[ROUTING] Protection table retained: %v", err)
		}
	}
	log.Println("[ROUTING] Routes restored.")
}

func startTun(ctx context.Context, cfg *Config, ready ...func()) error {
	tunName := cfg.TunName
	if tunName == "" {
		tunName = "atlant0"
	}
	effectiveMTU := cfg.MTU
	if effectiveMTU < 1200 || effectiveMTU > 9000 {
		effectiveMTU = defaultMTU
	}
	dev, err := tun.CreateTUN(tunName, effectiveMTU)
	if err != nil {
		return fmt.Errorf("create TUN interface %s (are you root?): %w", tunName, err)
	}
	defer dev.Close()

	tunAddr := cfg.TunAddr
	if tunAddr == "" {
		tunAddr = "10.254.1.2/24"
	}

	if out, err := exec.Command("ip", "addr", "add", tunAddr, "dev", tunName).CombinedOutput(); err != nil {
		return fmt.Errorf("configure TUN address: %w: %s", err, strings.TrimSpace(string(out)))
	}
	ipv6Addr := cfg.TunIPv6Addr
	if ipv6Addr == "" {
		ipv6Addr = "fd42:6174:6c61:6e74::2/64"
	}
	if !cfg.DisableIPv6 {
		ip, _, err := net.ParseCIDR(ipv6Addr)
		if err != nil || ip.To4() != nil {
			return fmt.Errorf("invalid IPv6 TUN address")
		}
		if out, err := exec.Command("ip", "-6", "addr", "add", ipv6Addr, "dev", tunName, "nodad").CombinedOutput(); err != nil {
			return fmt.Errorf("configure IPv6 TUN address: %w: %s", err, out)
		}
	}
	if out, err := exec.Command("ip", "link", "set", "mtu", fmt.Sprintf("%d", effectiveMTU), "up", "dev", tunName).CombinedOutput(); err != nil {
		return fmt.Errorf("bring TUN interface up: %w: %s", err, strings.TrimSpace(string(out)))
	}

	log.Printf("[TUN] Interface %s configured with IP %s", tunName, tunAddr)

	routes, rErr := setupLinuxRouting(cfg)
	if rErr != nil {
		return fmt.Errorf("VPN routes/protection not installed; refusing unprotected startup: %w", rErr)
	} else {
		activeRoutes = routes
		defer func() {
			cleanupLinuxRouting(routes)
			activeRoutes = nil
		}()
	}

	netStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	endpoint := &linkEndpoint{tun: dev, closed: make(chan struct{}), mtu: uint32(effectiveMTU)}
	defer func() { endpoint.Close(); netStack.Close() }()
	if err := netStack.CreateNIC(1, endpoint); err != nil {
		return fmt.Errorf("create TUN NIC: %s", err.String())
	}

	// Essential for VPN TUN intercept: accept packets for any destination IP and allow sending with any source IP
	if err := netStack.SetPromiscuousMode(1, true); err != nil {
		log.Printf("[TUN] Warning: SetPromiscuousMode error: %v", err)
	}
	if err := netStack.SetSpoofing(1, true); err != nil {
		log.Printf("[TUN] Warning: SetSpoofing error: %v", err)
	}

	tunIP, tunNet, parseErr := net.ParseCIDR(tunAddr)
	if parseErr != nil || tunIP.To4() == nil {
		return fmt.Errorf("invalid IPv4 TUN address %q", tunAddr)
	}
	tunIP = tunIP.To4()
	prefixLen, _ := tunNet.Mask.Size()
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(tunIP),
			PrefixLen: prefixLen,
		},
	}
	if err := netStack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("IPv4 stack address: %s", err)
	}
	if !cfg.DisableIPv6 {
		ip, subnet, _ := net.ParseCIDR(ipv6Addr)
		bits, _ := subnet.Mask.Size()
		if err := netStack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(ip.To16()), PrefixLen: bits}}, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("IPv6 stack address: %s", err)
		}
	}

	netStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	tcpForwarder := tcp.NewForwarder(netStack, 2*1024*1024, 65535, func(r *tcp.ForwarderRequest) {
		go handleTCP(r, cfg)
	})
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(netStack, func(r *udp.ForwarderRequest) bool {
		go handleUDP(r, cfg)
		return true
	})
	netStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	if len(ready) > 0 {
		ready[0]()
	}

	<-ctx.Done()
	endpoint.Close()
	return nil
}

func handleTCP(r *tcp.ForwarderRequest, cfg *Config) {
	reqDetails := r.ID()
	destAddr := net.JoinHostPort(reqDetails.LocalAddress.String(), strconv.Itoa(int(reqDetails.LocalPort)))

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	clientConn := gonet.NewTCPConn(&wq, ep)
	defer clientConn.Close()

	host, port, _ := net.SplitHostPort(destAddr)
	if cfg.FakeDNS && GetFakeDNS().IsFakeIP(host) {
		if dom, ok := GetFakeDNS().GetDomain(host); ok {
			destAddr = net.JoinHostPort(dom, port)
		}
	}

	remoteConn, err := dialRemote(cfg, "tcp", destAddr)
	if err != nil {
		log.Printf("[TCP] Failed to connect to %s: %v", destAddr, err)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		clientConn.Close()
		remoteConn.Close()
	}

	wg.Add(2)
	// Upload: clientConn -> remoteConn
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, err := io.CopyBuffer(remoteConn, clientConn, buf)
		if err != nil {
			closeOnce.Do(closeBoth)
			return
		}
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

func handleUDP(r *udp.ForwarderRequest, cfg *Config) {
	reqDetails := r.ID()
	destAddr := net.JoinHostPort(reqDetails.LocalAddress.String(), strconv.Itoa(int(reqDetails.LocalPort)))

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	gConn := gonet.NewUDPConn(&wq, ep)
	defer gConn.Close()

	// Intercept DNS queries (port 53)
	if reqDetails.LocalPort == 53 || strings.HasSuffix(destAddr, ":53") {
		buf := make([]byte, 2048)
		if err := gConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			reportDNSError("local query", &dnsExchangeError{"query deadline", err})
			return
		}
		n, err := gConn.Read(buf)
		if err == nil && n > 0 {
			if cfg.FakeDNS {
				if resp, errResp := RespondFakeDNS(buf[:n]); errResp == nil {
					if err := gConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
						reportDNSError("FakeDNS", &dnsExchangeError{"local deadline", err})
						return
					}
					written, err := gConn.Write(resp)
					if err == nil && written != len(resp) {
						err = io.ErrShortWrite
					}
					if err != nil {
						reportDNSError("FakeDNS", &dnsExchangeError{"local response", err})
					}
					return
				}
			}
			dnsTarget, err := dnsEndpoint(cfg.TunDNS)
			if err != nil {
				reportDNSError(cfg.TunDNS, err)
				return
			}
			response, err := exchangeDNS(buf[:n], dnsTarget, func(network, address string) (net.Conn, error) { return dialRemote(cfg, network, address) }, 3*time.Second)
			if err != nil {
				reportDNSError(dnsTarget, err)
				return
			}
			if err := gConn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				reportDNSError(dnsTarget, &dnsExchangeError{"local deadline", err})
				return
			}
			written, err := gConn.Write(response)
			if err == nil && written != len(response) {
				err = io.ErrShortWrite
			}
			if err != nil {
				reportDNSError(dnsTarget, &dnsExchangeError{"local response", err})
			}
		} else if err != nil {
			reportDNSError("local query", &dnsExchangeError{"query read", err})
		}
		return
	}

	h, p, _ := net.SplitHostPort(destAddr)
	if cfg.FakeDNS && GetFakeDNS().IsFakeIP(h) {
		if dom, ok := GetFakeDNS().GetDomain(h); ok {
			destAddr = net.JoinHostPort(dom, p)
		}
	}

	remoteConn, dialErr := dialRemote(cfg, "udp", destAddr)
	if dialErr != nil {
		log.Printf("[UDP] Failed to connect to %s: %v", destAddr, dialErr)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	var once sync.Once
	closeBoth := func() {
		gConn.Close()
		remoteConn.Close()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer once.Do(closeBoth)
		buf := make([]byte, 65535+2)
		for {
			n, err := gConn.Read(buf[2:])
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(buf[:2], uint16(n))
			if err := writeFull(remoteConn, buf[:2+n]); err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		defer once.Do(closeBoth)
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(remoteConn, lenBuf); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf)
			buf := make([]byte, length)
			if _, err := io.ReadFull(remoteConn, buf); err != nil {
				return
			}
			if _, err := gConn.Write(buf); err != nil {
				return
			}
		}
	}()

	wg.Wait()
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
