//go:build android || (linux && atlanttest)
// +build android linux,atlanttest

package atlant

import (
	"atlant.local/protocol/routepeek"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

type linkEndpoint struct {
	tun        tun.Device
	ctx        context.Context
	dispatcher stack.NetworkDispatcher
	dispatchMu sync.RWMutex
	readOnce   sync.Once
	fatal      chan error
	fatalOnce  sync.Once
	mtu        atomic.Uint32
}

func (e *linkEndpoint) fail(err error) {
	if err == nil {
		return
	}
	e.fatalOnce.Do(func() {
		select {
		case e.fatal <- err:
		default:
		}
	})
}

func (e *linkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatchMu.Lock()
	e.dispatcher = dispatcher
	e.dispatchMu.Unlock()
	if dispatcher == nil {
		return
	}
	e.readOnce.Do(func() {
		go func() {
			data := make([]byte, 65536)
			buffs := [][]byte{data}
			sizes := []int{0}
			for {
				select {
				case <-e.ctx.Done():
					return
				default:
				}
				sizes[0] = 0
				n, err := e.tun.Read(buffs, sizes, 0)
				if err != nil {
					if e.ctx.Err() != nil {
						return
					}
					log.Printf("[TUN] Read stopped: %v", err)
					e.fail(fmt.Errorf("TUN read failed: %w", err))
					return
				}
				if n == 0 || sizes[0] == 0 {
					continue
				}
				var p tcpip.NetworkProtocolNumber
				ver := header.IPVersion(data[:sizes[0]])
				if ver == 4 {
					p = header.IPv4ProtocolNumber
				} else if ver == 6 {
					p = header.IPv6ProtocolNumber
				} else {
					continue
				}
				pktData := make([]byte, sizes[0])
				copy(pktData, data[:sizes[0]])
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pktData)})
				e.dispatchMu.RLock()
				activeDispatcher := e.dispatcher
				e.dispatchMu.RUnlock()
				if activeDispatcher != nil {
					activeDispatcher.DeliverNetworkPacket(p, pkt)
				}
				pkt.DecRef()
			}
		}()
	})
}

func (e *linkEndpoint) IsAttached() bool {
	e.dispatchMu.RLock()
	defer e.dispatchMu.RUnlock()
	return e.dispatcher != nil
}
func (e *linkEndpoint) MTU() uint32 {
	if mtu := e.mtu.Load(); mtu != 0 {
		return mtu
	}
	return uint32(defaultMTU)
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
func (e *linkEndpoint) SetMTU(mtu uint32)                            { e.mtu.Store(mtu) }
func (e *linkEndpoint) AddHeader(pkt *stack.PacketBuffer)            {}

func (e *linkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		view := pkt.ToView()
		_, err := e.tun.Write([][]byte{view.AsSlice()}, 0)
		view.Release()
		if err != nil {
			log.Printf("[TUN] Write error: %v", err)
			e.fail(fmt.Errorf("TUN write failed: %w", err))
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}

func startTun(ctx context.Context, cfg *Config, tunFd int, ready chan<- error) {
	defer func() {
		mu.Lock()
		if vpnStack != nil {
			vpnStack.Close()
			vpnStack = nil
		}
		if tunDevice != nil {
			_ = tunDevice.Close()
			tunDevice = nil
		}
		mu.Unlock()
	}()
	log.Println("[Android] Starting TUN...")
	var err error
	tunDevice, _, err = tun.CreateUnmonitoredTUNFromFD(tunFd)
	if err != nil {
		log.Printf("[Android] Failed to create TUN from FD: %v", err)
		ready <- fmt.Errorf("create TUN from fd: %w", err)
		return
	}
	// A local TUN alone does not mean the remote endpoint is usable. Check
	// authentication before announcing readiness; the deferred cleanup closes
	// the owned TUN descriptor on failure so Android can restore its routes.
	probe, err := dialRealityConn(cfg)
	if err != nil {
		ready <- fmt.Errorf("authenticate VPN server before starting TUN: %w", err)
		return
	}
	_ = probe.Close()
	s, err := createStack()
	if err != nil {
		log.Printf("[Android] Failed to create stack: %v", err)
		ready <- fmt.Errorf("create network stack: %w", err)
		return
	}
	vpnStack = s

	linkEP := &linkEndpoint{tun: tunDevice, ctx: ctx, fatal: make(chan error, 1)}
	if cfg.TunMTU > 0 {
		linkEP.SetMTU(uint32(cfg.TunMTU))
	}
	if err := vpnStack.CreateNIC(1, linkEP); err != nil {
		log.Printf("[Android] Failed to create NIC: %v", err)
		ready <- fmt.Errorf("create TUN NIC: %s", err.String())
		return
	}
	vpnStack.SetPromiscuousMode(1, true)
	vpnStack.SetSpoofing(1, true)

	addr, err := netip.ParseAddr(cfg.TunAddr)
	if err != nil {
		log.Printf("[Android] Failed to parse TUN address: %v", err)
		ready <- fmt.Errorf("parse TUN address: %w", err)
		return
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: cfg.TunPrefixLen,
		},
	}
	if err := vpnStack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		log.Printf("[Android] Failed to add protocol address: %v", err)
		ready <- fmt.Errorf("add TUN address: %s", err.String())
		return
	}
	protoAddr6 := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP("fd00::2").To16()),
			PrefixLen: 120,
		},
	}
	_ = vpnStack.AddProtocolAddress(1, protoAddr6, stack.AddressProperties{})
	vpnStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})

	// 2MB receive window enables unthrottled gigabit speeds across high RTT
	tcpForwarder := tcp.NewForwarder(vpnStack, 2*1024*1024, 65535, func(r *tcp.ForwarderRequest) {
		go handleTCP(r, cfg)
	})
	vpnStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(vpnStack, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		// mDNS is link-local and must not leave the device.
		if id.LocalPort == 5353 {
			return false
		}
		destAddr := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return false
		}
		go handleUDP(ep, &wq, cfg, destAddr)
		return true
	})
	vpnStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	log.Println("[Android] VPN started successfully")
	ready <- nil
	select {
	case <-ctx.Done():
	case err := <-linkEP.fatal:
		log.Printf("[Android] Fatal TUN failure: %v", err)
		reportTunnelFailure(err)
	}
	log.Println("[Android] VPN stopping...")
}

func createStack() (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	// Enable SACK to prevent mobile throughput collapse upon packet drop
	sackOpt := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackOpt)

	// Enable dynamic moderate receive buffer scaling
	bufOpt := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &bufOpt)

	// Set Cubic congestion control for smooth high-bandwidth recovery
	ccOpt := tcpip.CongestionControlOption("cubic")
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt)

	return s, nil
}

func handleTCP(r *tcp.ForwarderRequest, cfg *Config) {
	reqID := r.ID()
	destAddr := net.JoinHostPort(reqID.LocalAddress.String(), strconv.Itoa(int(reqID.LocalPort)))
	host, port, _ := net.SplitHostPort(destAddr)
	if IsFakeDnsEnabled() && getFakeDNS().isFakeIPStr(host) {
		if dom, ok := getFakeDNS().lookupDomain(host); ok {
			destAddr = net.JoinHostPort(dom, port)
		}
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)

	clientConn := gonet.NewTCPConn(&wq, ep)
	defer clientConn.Close()

	// Peek initial packet (up to 4KB) to sniff TLS SNI or HTTP Host (skip for Server-Speaks-First protocols)
	var initialData []byte
	isServerFirst := strings.HasSuffix(destAddr, ":22") || strings.HasSuffix(destAddr, ":21") ||
		strings.HasSuffix(destAddr, ":25") || strings.HasSuffix(destAddr, ":110") ||
		strings.HasSuffix(destAddr, ":143") || strings.HasSuffix(destAddr, ":587")

	routeMu.RLock()
	needSniff := (routeMode == "rules" || routeMode == "proxy" || len(directDomains) > 0)
	routeMu.RUnlock()

	h, _, _ := net.SplitHostPort(destAddr)
	isFakeTarget := getFakeDNS().isFakeIPStr(h)

	if !isServerFirst && (needSniff || isFakeTarget) {
		initialData = routepeek.Read(clientConn, 400*time.Millisecond)
		if len(initialData) > 0 {
			if isFakeTarget {
				if sni := routepeek.ServerName(initialData); sni != "" {
					destAddr = net.JoinHostPort(sni, port)
					log.Printf("[SNI-RECOVER] Repaired fake IP %s -> %s from TLS ClientHello", h, destAddr)
				} else if hHost := routepeek.HTTPHost(initialData); hHost != "" {
					destAddr = net.JoinHostPort(hHost, port)
					log.Printf("[SNI-RECOVER] Repaired fake IP %s -> %s from HTTP Host", h, destAddr)
				}
			}
		}
	}

	direct := !mustProxyApp(clientConn, 6) && isDirect(destAddr, initialData)

	var remoteConn net.Conn
	var err error

	if direct {
		log.Printf("[TCP-DIRECT] Bypass VPN -> %s", destAddr)
		remoteConn, err = dialDirect("tcp", destAddr, 10*time.Second)
		if err != nil {
			log.Printf("[TCP-DIRECT] Direct dial failed for %s: %v; keeping the explicit bypass rule", destAddr, err)
		}
	} else {
		log.Printf("[TCP-VPN] Route via VPN -> %s", destAddr)
		remoteConn, err = dialTCPVPN(cfg, destAddr)
	}

	if err != nil {
		log.Printf("[TCP] Failed to connect -> %s: %v", destAddr, err)
		return
	}
	defer remoteConn.Close()

	if len(initialData) > 0 {
		if _, wErr := remoteConn.Write(initialData); wErr != nil {
			log.Printf("[TCP] Failed to forward initial packet to %s: %v", destAddr, wErr)
			return
		}
	}

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
		// but KEEP remoteConn open so the download goroutine can finish reading the complete media/sticker response!
		if cw, ok := remoteConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Download: remoteConn -> clientConn
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*1024)
		_, _ = io.CopyBuffer(clientConn, remoteConn, buf)
		// Server finished transmitting response (or connection reset)
		closeOnce.Do(closeBoth)
	}()

	wg.Wait()
	closeOnce.Do(closeBoth)
}

func handleUDP(ep tcpip.Endpoint, wq *waiter.Queue, cfg *Config, destAddr string) {
	handleUDPConn(gonet.NewUDPConn(wq, ep), cfg, destAddr)
}

func handleUDPConn(gConn net.Conn, cfg *Config, destAddr string) {
	defer gConn.Close()

	log.Printf("[UDP] %s", destAddr)

	// DNS queries (port 53)
	if strings.HasSuffix(destAddr, ":53") {
		dnsTarget := destAddr
		if strings.HasPrefix(destAddr, "172.19.0.") {
			dnsTarget = "1.1.1.1:53"
		}
		if !IsRemoteDnsEnabled() {
			routeDNSDirect(gConn, dnsTarget)
			return
		}
		var firstPkt []byte
		if IsFakeDnsEnabled() {
			buf := make([]byte, 2048)
			_ = gConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := gConn.Read(buf)
			if err == nil && n > 0 {
				if resp, ok := getFakeDNS().handleDNSQuery(buf[:n]); ok {
					_ = gConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					_, _ = gConn.Write(resp)
					return // Responded in 0.1ms locally!
				}
				firstPkt = make([]byte, n)
				copy(firstPkt, buf[:n])
			}
		}
		routeUDPViaTCP(gConn, cfg, dnsTarget, firstPkt)
		return
	}

	host, port, _ := net.SplitHostPort(destAddr)
	if IsFakeDnsEnabled() && getFakeDNS().isFakeIPStr(host) {
		if dom, ok := getFakeDNS().lookupDomain(host); ok {
			destAddr = net.JoinHostPort(dom, port)
		}
	}

	var initialHello []byte
	mustProxy := mustProxyApp(gConn, 17)
	if needsDomainSniff(destAddr) && !mustProxy {
		gConn, initialHello = routepeek.ReadQUIC(gConn, 400*time.Millisecond)
	}
	if !mustProxy && isDirect(destAddr, initialHello) {
		log.Printf("[UDP-DIRECT] Bypass VPN -> %s", destAddr)
		directConn, err := dialDirect("udp", destAddr, 10*time.Second)
		if err != nil {
			log.Printf("[UDP-DIRECT] Direct dial failed for %s: %v; keeping the explicit bypass rule", destAddr, err)
			return
		}
		defer directConn.Close()
		var wg sync.WaitGroup
		var once sync.Once
		closeBoth := func() {
			_ = gConn.Close()
			_ = directConn.Close()
		}
		wg.Add(2)
		relay := func(dst, src net.Conn) {
			defer wg.Done()
			defer once.Do(closeBoth)
			buf := make([]byte, 65535)
			for {
				_ = src.SetReadDeadline(time.Now().Add(60 * time.Second))
				n, rErr := src.Read(buf)
				if rErr != nil {
					return
				}
				if _, wErr := dst.Write(buf[:n]); wErr != nil {
					return
				}
			}
		}
		go relay(directConn, gConn)
		go relay(gConn, directConn)
		wg.Wait()
		return
	}

	if cfg.UDPMode != "tcp" && !isUDPBlocked() {
		if ok := handleUDPViaDatagramTunnel(gConn, cfg, destAddr); ok {
			return
		}
		// QUIC UDP datagram blocked or timed out, switch to TCP Reality
		log.Printf("[QUIC-UDP] UDP datagram blocked or timed out, falling back to TCP Reality")
		setUDPBlocked(true)
		startUDPRecoveryProbe(cfg)
	}

	routeUDPViaTCP(gConn, cfg, destAddr, nil)
}

// Direct DNS explicitly bypasses the VPN only when selected by the user.
// Keep one protected UDP socket per client flow and retain learned addresses
// for domain routing when FakeDNS is disabled for these queries.
func routeDNSDirect(client net.Conn, target string) {
	upstream, err := dialDirect("udp", target, 3*time.Second)
	if err != nil {
		log.Printf("[DNS-DIRECT] Dial failed: %v", err)
		return
	}
	defer upstream.Close()
	var wg sync.WaitGroup
	var once sync.Once
	closeBoth := func() { _ = client.Close(); _ = upstream.Close() }
	relay := func(dst, src net.Conn, response bool) {
		defer wg.Done()
		defer once.Do(closeBoth)
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if response {
				learnDNSResponse(buf[:n])
			}
			_ = dst.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if written, err := dst.Write(buf[:n]); err != nil || written != n {
				return
			}
		}
	}
	wg.Add(2)
	go relay(upstream, client, false)
	go relay(client, upstream, true)
	wg.Wait()
}

func dialTCPVPN(cfg *Config, destAddr string) (net.Conn, error) {
	proto := GetTCPProto()
	if proto == "udp" || proto == "quic" {
		conn, err := dialQUICStream(cfg, "tcp", destAddr)
		if err == nil {
			return conn, nil
		}
		if !IsAutoFallbackEnabled() {
			return nil, err
		}
		log.Printf("[TCP-VPN] QUIC stream failed (%v), falling back to direct Reality", err)
	}
	if proto == "xhttp" {
		conn, err := dialXHTTPStream(cfg, "tcp", destAddr)
		if err == nil {
			return conn, nil
		}
		if !IsAutoFallbackEnabled() {
			return nil, err
		}
		log.Printf("[TCP-VPN] XHTTP stream failed (%v), falling back to direct Reality", err)
	}
	return dialRealityTransport(cfg, "tcp", destAddr)
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
