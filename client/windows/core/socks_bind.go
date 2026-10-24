package main

import (
	"fmt"
	"net"
	"strconv"
)

// Honor AllowLAN for explicit wildcard/IP binds too, not only ":port".
func socksBindAddress(address string, allowLAN bool) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return "", fmt.Errorf("invalid SOCKS port")
	}
	ip := net.ParseIP(host)
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		if !allowLAN {
			host = "127.0.0.1"
		} else if host == "" {
			host = "0.0.0.0"
		}
	} else if !allowLAN && host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("non-loopback SOCKS bind requires allow_lan=true")
	}
	return net.JoinHostPort(host, port), nil
}
