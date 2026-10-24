package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

// FakeDNSEngine manages a virtual IPv4 pool (198.18.0.0/15) according to RFC 2544.
type FakeDNSEngine struct {
	mu           sync.RWMutex
	domainToIP   map[string]string
	ipToDomain   map[string]string
	currentIPNum uint32
	startIPNum   uint32
	endIPNum     uint32
}

var (
	globalFakeDNS *FakeDNSEngine
	fakeDNSOnce   sync.Once
	fakeNetCIDR   *net.IPNet
)

func init() {
	_, fakeNetCIDR, _ = net.ParseCIDR("198.18.0.0/15")
}

func GetFakeDNS() *FakeDNSEngine {
	fakeDNSOnce.Do(func() {
		start := ipToUint32(net.ParseIP("198.18.0.2"))
		end := ipToUint32(net.ParseIP("198.19.255.254"))
		globalFakeDNS = &FakeDNSEngine{
			domainToIP:   make(map[string]string),
			ipToDomain:   make(map[string]string),
			currentIPNum: start,
			startIPNum:   start,
			endIPNum:     end,
		}
	})
	return globalFakeDNS
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func (e *FakeDNSEngine) GetOrAllocateIP(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	e.mu.Lock()
	defer e.mu.Unlock()

	if ip, exists := e.domainToIP[domain]; exists {
		return ip
	}

	ipStr := uint32ToIP(e.currentIPNum).String()
	if oldDomain, occupied := e.ipToDomain[ipStr]; occupied {
		delete(e.domainToIP, oldDomain)
	}

	e.domainToIP[domain] = ipStr
	e.ipToDomain[ipStr] = domain

	e.currentIPNum++
	if e.currentIPNum > e.endIPNum {
		e.currentIPNum = e.startIPNum
	}

	return ipStr
}

func (e *FakeDNSEngine) GetDomain(ipStr string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	domain, ok := e.ipToDomain[ipStr]
	return domain, ok
}

func (e *FakeDNSEngine) IsFakeIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return fakeNetCIDR.Contains(ip)
}

func RespondFakeDNS(rawReq []byte) ([]byte, error) {
	if len(rawReq) < 12 {
		return nil, fmt.Errorf("DNS request too short")
	}

	domain, qtype, qclass, err := parseDNSQuery(rawReq)
	if err != nil {
		return nil, err
	}

	if qtype != 1 || qclass != 1 {
		return nil, fmt.Errorf("only A record queries supported")
	}

	fakeIP := GetFakeDNS().GetOrAllocateIP(domain)
	ipObj := net.ParseIP(fakeIP).To4()
	if ipObj == nil {
		return nil, fmt.Errorf("invalid allocated fake IP")
	}

	resp := make([]byte, len(rawReq))
	copy(resp, rawReq)

	resp[2] = 0x81
	resp[3] = 0x80

	resp[6] = 0x00
	resp[7] = 0x01

	resp = append(resp, 0xc0, 0x0c)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x05)
	resp = append(resp, 0x00, 0x04)
	resp = append(resp, ipObj...)

	return resp, nil
}

func parseDNSQuery(b []byte) (domain string, qtype uint16, qclass uint16, err error) {
	if len(b) < 12 {
		return "", 0, 0, fmt.Errorf("packet too short")
	}

	curr := 12
	qEnd := -1
	var parts []string
	hops := 0

	for curr < len(b) {
		l := int(b[curr])
		if l == 0 {
			if qEnd == -1 {
				qEnd = curr + 1
			}
			break
		}
		if (l & 0xC0) == 0xC0 {
			// RFC 1035 Compression Pointer
			if curr+1 >= len(b) {
				return "", 0, 0, fmt.Errorf("truncated compression pointer")
			}
			ptr := int(l&0x3F)<<8 | int(b[curr+1])
			if qEnd == -1 {
				qEnd = curr + 2
			}
			hops++
			if hops > 10 {
				return "", 0, 0, fmt.Errorf("compression pointer loop detected")
			}
			if ptr >= len(b) {
				return "", 0, 0, fmt.Errorf("pointer beyond buffer bounds")
			}
			curr = ptr
			continue
		}

		// Normal label
		curr++
		if curr+l > len(b) {
			return "", 0, 0, fmt.Errorf("malformed question label length")
		}
		parts = append(parts, string(b[curr:curr+l]))
		curr += l
	}

	if qEnd == -1 {
		qEnd = curr
	}

	if qEnd+4 > len(b) {
		return "", 0, 0, fmt.Errorf("truncated query tail")
	}

	qtype = binary.BigEndian.Uint16(b[qEnd : qEnd+2])
	qclass = binary.BigEndian.Uint16(b[qEnd+2 : qEnd+4])
	domain = strings.Join(parts, ".")
	return domain, qtype, qclass, nil
}
