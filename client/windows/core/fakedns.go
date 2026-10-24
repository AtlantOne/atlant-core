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

// GetFakeDNS returns the singleton FakeDNS engine.
func GetFakeDNS() *FakeDNSEngine {
	fakeDNSOnce.Do(func() {
		start := ipToUint32(net.ParseIP("198.18.0.2").To4())
		end := ipToUint32(net.ParseIP("198.19.255.254").To4())
		globalFakeDNS = &FakeDNSEngine{
			domainToIP:   make(map[string]string, 4096),
			ipToDomain:   make(map[string]string, 4096),
			currentIPNum: start,
			startIPNum:   start,
			endIPNum:     end,
		}
	})
	return globalFakeDNS
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func uint32ToIP(n uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return net.IP(b)
}

func (f *FakeDNSEngine) IsFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return fakeNetCIDR.Contains(ip4)
}

func (f *FakeDNSEngine) IsFakeIPStr(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return f.IsFakeIP(ip)
}

func (f *FakeDNSEngine) LookupDomain(ipStr string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	dom, ok := f.ipToDomain[ipStr]
	return dom, ok
}

func (f *FakeDNSEngine) Allocate(domain string) net.IP {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if ipStr, ok := f.domainToIP[domain]; ok {
		return net.ParseIP(ipStr)
	}

	cur := f.currentIPNum
	f.currentIPNum++
	if f.currentIPNum >= f.endIPNum {
		f.currentIPNum = f.startIPNum
	}

	newIP := uint32ToIP(cur)
	ipStr := newIP.String()

	if oldDom, exists := f.ipToDomain[ipStr]; exists {
		delete(f.domainToIP, oldDom)
	}

	f.domainToIP[domain] = ipStr
	f.ipToDomain[ipStr] = domain
	return newIP
}

func ParseQuestionDomain(data []byte) (string, uint16, int, error) {
	if len(data) < 12 {
		return "", 0, 0, fmt.Errorf("packet too short")
	}
	qdCount := binary.BigEndian.Uint16(data[4:6])
	if qdCount == 0 {
		return "", 0, 0, fmt.Errorf("no questions")
	}

	curr := 12
	qEnd := -1
	var domainParts []string
	hops := 0

	for curr < len(data) {
		l := int(data[curr])
		if l == 0 {
			if qEnd == -1 {
				qEnd = curr + 1
			}
			break
		}
		if (l & 0xC0) == 0xC0 {
			// RFC 1035 Compression Pointer (2 bytes)
			if curr+1 >= len(data) {
				return "", 0, 0, fmt.Errorf("truncated compression pointer")
			}
			ptr := int(l&0x3F)<<8 | int(data[curr+1])
			if qEnd == -1 {
				qEnd = curr + 2
			}
			hops++
			if hops > 10 {
				return "", 0, 0, fmt.Errorf("compression pointer loop detected")
			}
			if ptr >= len(data) {
				return "", 0, 0, fmt.Errorf("pointer beyond buffer bounds")
			}
			curr = ptr
			continue
		}

		// Normal label
		curr++
		if curr+l > len(data) {
			return "", 0, 0, fmt.Errorf("malformed question label length")
		}
		domainParts = append(domainParts, string(data[curr:curr+l]))
		curr += l
	}

	if qEnd == -1 {
		qEnd = curr
	}

	if qEnd+4 > len(data) {
		return "", 0, 0, fmt.Errorf("question header truncated")
	}
	qType := binary.BigEndian.Uint16(data[qEnd : qEnd+2])
	domain := strings.ToLower(strings.Join(domainParts, "."))
	return domain, qType, qEnd + 4, nil
}

func (f *FakeDNSEngine) HandleDNSQuery(queryData []byte) ([]byte, bool) {
	if len(queryData) < 12 {
		return nil, false
	}
	if queryData[2]&0x80 != 0 {
		return nil, false
	}

	txID := queryData[:2]
	domain, qType, questionEnd, err := ParseQuestionDomain(queryData)
	if err != nil || domain == "" || questionEnd > len(queryData) {
		return nil, false
	}

	questionSection := queryData[12:questionEnd]

	if qType == 1 {
		fakeIP := f.Allocate(domain)
		ip4 := fakeIP.To4()
		if ip4 == nil {
			return nil, false
		}

		resp := make([]byte, 0, 12+len(questionSection)+16)
		resp = append(resp, txID...)
		resp = append(resp, 0x81, 0x80)
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, questionSection...)
		resp = append(resp, 0xc0, 0x0c)
		resp = append(resp, 0x00, 0x01, 0x00, 0x01)
		resp = append(resp, 0x00, 0x00, 0x00, 0x0a) // 10s TTL prevents DNS cache churn
		resp = append(resp, 0x00, 0x04)
		resp = append(resp, ip4...)
		return resp, true
	}

	// Type 28 (AAAA) and Type 65 (HTTPS / SVCB): reply with instant NODATA (0 answers, NOERROR)
	if qType == 28 || qType == 65 {
		resp := make([]byte, 0, 12+len(questionSection))
		resp = append(resp, txID...)
		resp = append(resp, 0x81, 0x80)
		resp = append(resp, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		resp = append(resp, questionSection...)
		return resp, true
	}

	return nil, false
}
