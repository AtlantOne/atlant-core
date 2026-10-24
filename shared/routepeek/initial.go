// Package routepeek collects a bounded prefix without discarding bytes needed
// by the application. An unidentified name is not permission to bypass a VPN.
package routepeek

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const MaxPrefix = 64 << 10

func Read(conn net.Conn, timeout time.Duration) []byte {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	defer conn.SetReadDeadline(time.Time{})
	data := make([]byte, 0, 4096)
	for len(data) < MaxPrefix {
		chunk := make([]byte, min(4096, MaxPrefix-len(data)))
		n, err := conn.Read(chunk)
		data = append(data, chunk[:n]...)
		if complete(data) || err != nil || n == 0 {
			break
		}
	}
	return data
}

func clientHello(data []byte) ([]byte, bool) {
	var handshake []byte
	for len(data) >= 5 {
		if data[0] != 22 || data[1] != 3 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if n == 0 || n > 18432 || len(data) < 5+n {
			return nil, false
		}
		handshake = append(handshake, data[5:5+n]...)
		if len(handshake) >= 4 {
			if handshake[0] != 1 {
				return nil, false
			}
			length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if length > MaxPrefix-4 {
				return nil, false
			}
			if len(handshake) >= 4+length {
				return handshake[4 : 4+length], true
			}
		}
		data = data[5+n:]
	}
	return nil, false
}

func complete(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if data[0] == 22 {
		_, ok := clientHello(data)
		return ok
	}
	for _, method := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "} {
		if bytes.HasPrefix(data, []byte(method)) || bytes.HasPrefix([]byte(method), data) {
			return bytes.Contains(data, []byte("\r\n\r\n"))
		}
	}
	return true
}

func ServerName(data []byte) string {
	hello, ok := clientHello(data)
	if !ok || len(hello) < 35 {
		return ""
	}
	i := 35 + int(hello[34])
	if i+2 > len(hello) {
		return ""
	}
	i += 2 + int(binary.BigEndian.Uint16(hello[i:i+2]))
	if i >= len(hello) {
		return ""
	}
	i += 1 + int(hello[i])
	if i+2 > len(hello) {
		return ""
	}
	n := int(binary.BigEndian.Uint16(hello[i : i+2]))
	i += 2
	if n != len(hello)-i {
		return ""
	}
	for i+4 <= len(hello) {
		typ := binary.BigEndian.Uint16(hello[i : i+2])
		size := int(binary.BigEndian.Uint16(hello[i+2 : i+4]))
		i += 4
		if size > len(hello)-i {
			return ""
		}
		if typ == 0 {
			ext := hello[i : i+size]
			if len(ext) < 5 || int(binary.BigEndian.Uint16(ext[:2])) != len(ext)-2 {
				return ""
			}
			for j := 2; j+3 <= len(ext); {
				nameType := ext[j]
				length := int(binary.BigEndian.Uint16(ext[j+1 : j+3]))
				j += 3
				if length > len(ext)-j {
					return ""
				}
				if nameType == 0 {
					return validName(string(ext[j : j+length]))
				}
				j += length
			}
			return ""
		}
		i += size
	}
	return ""
}

func validName(s string) string {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 || strings.ContainsAny(s, " /\\\r\n\t\x00") {
		return ""
	}
	return s
}

func HTTPHost(data []byte) string {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return ""
	}
	lines := strings.Split(string(data[:end]), "\r\n")
	if len(lines) == 0 || !strings.Contains(lines[0], " HTTP/1.") {
		return ""
	}
	var host string
	for _, line := range lines[1:] {
		key, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(key, "Host") {
			continue
		}
		if host != "" {
			return ""
		}
		host = strings.TrimSpace(value)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return validName(host)
}
