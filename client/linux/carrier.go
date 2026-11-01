package main

import "strings"

// Traffic policy takes precedence over a saved carrier preference. In split
// mode, selecting XHTTP for TCP must not capture UDP configured for QUIC.
func linuxCarrier(cfg *Config, network string) string {
	mode := strings.ToLower(cfg.TrafficMode)
	tcp := strings.ToLower(cfg.TCPProto)
	if mode == "udp" {
		return "quic"
	}
	if mode == "tcp" {
		if tcp == "xhttp" {
			return "xhttp"
		}
		return "reality"
	}
	transport := strings.ToLower(cfg.Transport)
	if transport == "quic" {
		return "quic"
	}
	if network == "udp" && strings.EqualFold(cfg.UDPProto, "quic") {
		return "quic"
	}
	if transport == "xhttp" || tcp == "xhttp" {
		return "xhttp"
	}
	if network == "tcp" && tcp == "quic" {
		return "quic"
	}
	return "reality"
}
