package main

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// InboundSpec owns connection settings. Subscription references must not carry
// editable copies of SNI, transport settings or server private keys.
type InboundSpec struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Enabled       bool        `json:"enabled"`
	Listen        string      `json:"listen"`
	AdvertiseAddr string      `json:"advertise_addr"`
	SNI           string      `json:"sni"`
	Transports    []string    `json:"transports"`
	WireVersion   int         `json:"wire_version"`
	XHTTPPath     string      `json:"xhttp_path"`
	UpMbps        uint64      `json:"up_mbps"`
	DownMbps      uint64      `json:"down_mbps"`
	Quic          QuicConfig  `json:"quic"`
	Yamux         YamuxConfig `json:"yamux"`
}

type SubscriptionInboundRef struct {
	ServerID  string `json:"server_id"`
	InboundID string `json:"inbound_id"`
}

type resolvedSubscriptionInbound struct {
	ServerID string
	Spec     InboundSpec
}

func resolveInboundRefs(refs []SubscriptionInboundRef, servers map[string]map[string]InboundSpec) ([]resolvedSubscriptionInbound, error) {
	if len(refs) > 256 {
		return nil, errors.New("too many subscription inbound references")
	}
	seen := map[SubscriptionInboundRef]bool{}
	result := make([]resolvedSubscriptionInbound, 0, len(refs))
	for _, ref := range refs {
		if !inboundIDPattern.MatchString(ref.ServerID) || !inboundIDPattern.MatchString(ref.InboundID) || seen[ref] {
			return nil, errors.New("invalid or duplicate subscription inbound reference")
		}
		seen[ref] = true
		spec, ok := servers[ref.ServerID][ref.InboundID]
		if !ok || spec.ID != ref.InboundID {
			return nil, errors.New("subscription references an unknown inbound")
		}
		if err := spec.validate(); err != nil {
			return nil, err
		}
		spec.Transports = append([]string(nil), spec.Transports...)
		result = append(result, resolvedSubscriptionInbound{ServerID: ref.ServerID, Spec: spec})
	}
	return result, nil
}

var inboundIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var inboundDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func inboundBind(address string) (netip.Addr, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, 0, errors.New("inbound requires a literal IP bind address and port")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return netip.Addr{}, 0, errors.New("inbound port must be 1-65535")
	}
	if host == "" {
		return netip.IPv6Unspecified(), uint16(p), nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.IsMulticast() {
		return netip.Addr{}, 0, errors.New("inbound bind address must be a literal unscoped unicast IP")
	}
	return ip.Unmap(), uint16(p), nil
}

func (s InboundSpec) validate() error {
	if !inboundIDPattern.MatchString(s.ID) || len(strings.TrimSpace(s.Name)) == 0 || len(s.Name) > 256 || strings.ContainsAny(s.Name, "\r\n\x00") {
		return errors.New("invalid inbound ID or name")
	}
	if _, _, err := inboundBind(s.Listen); err != nil {
		return err
	}
	if s.WireVersion != 7 || len(s.Transports) == 0 || len(s.Transports) > 3 || s.UpMbps > 1000000 || s.DownMbps > 1000000 {
		return errors.New("inbound requires wire7, explicit transports and valid rate limits")
	}
	if err := s.validateTuning(); err != nil {
		return err
	}
	if len(s.SNI) > 253 || !strings.Contains(s.SNI, ".") {
		return errors.New("invalid inbound REALITY server name")
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(s.SNI, ".")); err == nil {
		return errors.New("inbound REALITY server name must be a DNS name")
	}
	for _, label := range strings.Split(strings.TrimSuffix(s.SNI, "."), ".") {
		if !inboundDNSLabel.MatchString(label) {
			return errors.New("invalid inbound REALITY server name")
		}
	}
	seen := map[string]bool{}
	for _, transport := range s.Transports {
		if seen[transport] || (transport != "tcp" && transport != "xhttp" && transport != "quic") {
			return errors.New("invalid or duplicate inbound transport")
		}
		seen[transport] = true
	}
	if seen["xhttp"] && (len(s.XHTTPPath) < 1 || len(s.XHTTPPath) > 1024 || !strings.HasPrefix(s.XHTTPPath, "/") || strings.ContainsAny(s.XHTTPPath, "?#\r\n\x00")) {
		return errors.New("invalid inbound XHTTP path")
	}
	if s.AdvertiseAddr != "" {
		host, port, err := net.SplitHostPort(s.AdvertiseAddr)
		p, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || p == 0 || host == "" || strings.ContainsAny(host, " /\r\n\t\x00") {
			return errors.New("invalid public inbound endpoint")
		}
	}
	return nil
}

// Zero selects the transport default. Bound values before converting them to
// durations or byte windows, including on 32-bit client and server builds.
func (s InboundSpec) validateTuning() error {
	q, y := s.Quic, s.Yamux
	if q.MaxIdleTimeoutSec < 0 || q.MaxIdleTimeoutSec > 86400 ||
		q.KeepAlivePeriodSec < 0 || q.KeepAlivePeriodSec > 3600 ||
		q.StreamReceiveWindowMB < 0 || q.StreamReceiveWindowMB > 256 ||
		q.ConnReceiveWindowMB < 0 || q.ConnReceiveWindowMB > 1024 ||
		q.SocketBufferSizeMB < 0 || q.SocketBufferSizeMB > 64 {
		return errors.New("inbound QUIC tuning exceeds supported bounds")
	}
	c := &Config{Quic: q}
	if c.GetQuicKeepAlivePeriod() >= c.GetQuicMaxIdleTimeout() || c.GetQuicConnReceiveWindow() < c.GetQuicStreamReceiveWindow() {
		return errors.New("inbound QUIC keepalive/window settings conflict")
	}
	if y.MaxStreamWindowKB < 0 || (y.MaxStreamWindowKB != 0 && y.MaxStreamWindowKB < 256) || y.MaxStreamWindowKB > 256*1024 ||
		y.MaxConnectionWindowKB < 0 || y.MaxConnectionWindowKB > 1024*1024 ||
		y.KeepAlivePeriodSec < 0 || y.KeepAlivePeriodSec > 3600 || y.WriteTimeoutSec < 0 || y.WriteTimeoutSec > 3600 {
		return errors.New("inbound TCP tuning exceeds supported bounds")
	}
	return nil
}

func inboundNetworks(s InboundSpec) map[string]bool {
	networks := map[string]bool{}
	for _, transport := range s.Transports {
		if transport == "quic" {
			networks["udp"] = true
		} else {
			networks["tcp"] = true
		}
	}
	return networks
}

func validateInboundSet(specs []InboundSpec) error {
	if len(specs) > 256 {
		return errors.New("too many inbounds")
	}
	ids := map[string]bool{}
	for index, spec := range specs {
		if err := spec.validate(); err != nil {
			return err
		}
		if ids[spec.ID] {
			return errors.New("duplicate inbound ID")
		}
		ids[spec.ID] = true
		if !spec.Enabled {
			continue
		}
		ip, port, _ := inboundBind(spec.Listen)
		for _, other := range specs[:index] {
			if !other.Enabled {
				continue
			}
			otherIP, otherPort, _ := inboundBind(other.Listen)
			if port != otherPort || (ip != otherIP && !ip.IsUnspecified() && !otherIP.IsUnspecified()) {
				continue
			}
			for network := range inboundNetworks(spec) {
				if inboundNetworks(other)[network] {
					return errors.New("inbound listener conflicts with another enabled inbound")
				}
			}
		}
	}
	return nil
}
