// Package tlsaudit is a bounded, read-only audit helper, not a TLS parser used
// for authorization. Summaries are structural observations, NOT JA4 identities
// or evidence that an implementation is indistinguishable from a browser.
package tlsaudit

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
)

type Summary struct {
	RecordSizes         []int                `json:"record_sizes"`
	HelloSize           int                  `json:"hello_size"`
	SessionIDSize       int                  `json:"session_id_size"`
	CipherSuites        []uint16             `json:"cipher_suites"`
	Extensions          []uint16             `json:"extensions"`
	KeyShareGroups      []uint16             `json:"key_share_groups"`
	KeyShareSizes       []int                `json:"key_share_sizes"`
	ALPN                []string             `json:"alpn"`
	SupportedGroups     []uint16             `json:"supported_groups,omitempty"`
	SupportedVersions   []uint16             `json:"supported_versions,omitempty"`
	SignatureSchemes    []uint16             `json:"signature_schemes,omitempty"`
	TransportParameters []TransportParameter `json:"transport_parameters,omitempty"`
}

type TransportParameter struct {
	ID      uint64  `json:"id"`
	Length  int     `json:"length"`
	Integer *uint64 `json:"integer,omitempty"`
}

func integerList(body []byte, prefix int) ([]uint16, bool) {
	if len(body) < prefix {
		return nil, false
	}
	n := int(body[0])
	if prefix == 2 {
		n = int(binary.BigEndian.Uint16(body))
	}
	if n != len(body)-prefix || n%2 != 0 {
		return nil, false
	}
	var values []uint16
	for p := body[prefix:]; len(p) > 0; p = p[2:] {
		v := binary.BigEndian.Uint16(p)
		if !grease(v) {
			values = append(values, v)
		}
	}
	return values, true
}

func readVarint(p *[]byte) (uint64, bool) {
	if len(*p) == 0 {
		return 0, false
	}
	n := 1 << ((*p)[0] >> 6)
	if len(*p) < n {
		return 0, false
	}
	v := uint64((*p)[0] & 0x3f)
	for _, b := range (*p)[1:n] {
		v = v<<8 | uint64(b)
	}
	*p = (*p)[n:]
	return v, true
}

func transportParameters(p []byte) ([]TransportParameter, bool) {
	var result []TransportParameter
	seen := make(map[uint64]bool)
	for len(p) > 0 {
		id, ok := readVarint(&p)
		if !ok || seen[id] {
			return nil, false
		}
		seen[id] = true
		n, ok := readVarint(&p)
		if !ok || n > uint64(len(p)) {
			return nil, false
		}
		value := p[:int(n)]
		p = p[int(n):]
		parameter := TransportParameter{ID: id, Length: len(value)}
		// Only public numeric limits are exported. CID/token/opaque values
		// remain length-only even though an on-path observer can read them.
		switch id {
		case 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32:
			integer, ok := readVarint(&value)
			if !ok || len(value) != 0 {
				return nil, false
			}
			parameter.Integer = &integer
		}
		result = append(result, parameter)
	}
	return result, true
}

func grease(value uint16) bool { return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value) }

func Summarize(records []byte) (Summary, error) {
	var result Summary
	fail := errors.New("invalid or oversized ClientHello")
	if len(records) > 128<<10 {
		return result, fail
	}
	var handshake []byte
	for len(records) > 0 {
		if len(records) < 5 || records[0] != 0x16 || records[1] != 3 || records[2] > 3 {
			return result, fail
		}
		n := int(binary.BigEndian.Uint16(records[3:5]))
		if n < 1 || n > 16384 || len(records) < 5+n {
			return result, fail
		}
		result.RecordSizes = append(result.RecordSizes, n+5)
		handshake = append(handshake, records[5:5+n]...)
		records = records[5+n:]
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return result, fail
	}
	n := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if n != len(handshake)-4 {
		return result, fail
	}
	result.HelloSize = len(handshake)
	p := handshake[4:]
	take := func(n int) ([]byte, bool) {
		if n < 0 || len(p) < n {
			return nil, false
		}
		v := p[:n]
		p = p[n:]
		return v, true
	}
	if _, ok := take(34); !ok {
		return result, fail
	}
	sid, ok := take(1)
	if !ok || sid[0] > 32 {
		return result, fail
	}
	result.SessionIDSize = int(sid[0])
	if _, ok := take(int(sid[0])); !ok {
		return result, fail
	}
	length, ok := take(2)
	if !ok {
		return result, fail
	}
	suites, ok := take(int(binary.BigEndian.Uint16(length)))
	if !ok || len(suites) == 0 || len(suites)%2 != 0 {
		return result, fail
	}
	for len(suites) > 0 {
		v := binary.BigEndian.Uint16(suites)
		if !grease(v) {
			result.CipherSuites = append(result.CipherSuites, v)
		}
		suites = suites[2:]
	}
	compression, ok := take(1)
	if !ok {
		return result, fail
	}
	if _, ok := take(int(compression[0])); !ok {
		return result, fail
	}
	extLen, ok := take(2)
	if !ok || int(binary.BigEndian.Uint16(extLen)) != len(p) {
		return result, fail
	}
	seenExtensions := make(map[uint16]bool)
	for len(p) > 0 {
		header, ok := take(4)
		if !ok {
			return result, fail
		}
		kind := binary.BigEndian.Uint16(header)
		if seenExtensions[kind] {
			return result, fail
		}
		seenExtensions[kind] = true
		body, ok := take(int(binary.BigEndian.Uint16(header[2:])))
		if !ok {
			return result, fail
		}
		if !grease(kind) {
			result.Extensions = append(result.Extensions, kind)
		}
		switch kind {
		case 10:
			var ok bool
			result.SupportedGroups, ok = integerList(body, 2)
			if !ok {
				return result, fail
			}
		case 13:
			var ok bool
			result.SignatureSchemes, ok = integerList(body, 2)
			if !ok {
				return result, fail
			}
		case 43:
			var ok bool
			result.SupportedVersions, ok = integerList(body, 1)
			if !ok {
				return result, fail
			}
		case 57:
			var ok bool
			result.TransportParameters, ok = transportParameters(body)
			if !ok {
				return result, fail
			}
		case 51:
			if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
				return result, fail
			}
			body = body[2:]
			for len(body) > 0 {
				if len(body) < 4 {
					return result, fail
				}
				group := binary.BigEndian.Uint16(body)
				size := int(binary.BigEndian.Uint16(body[2:]))
				body = body[4:]
				if size > len(body) {
					return result, fail
				}
				if !grease(group) {
					result.KeyShareGroups = append(result.KeyShareGroups, group)
					result.KeyShareSizes = append(result.KeyShareSizes, size)
				}
				body = body[size:]
			}
		case 16:
			if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
				return result, fail
			}
			body = body[2:]
			for len(body) > 0 {
				size := int(body[0])
				body = body[1:]
				if size == 0 || size > len(body) {
					return result, fail
				}
				result.ALPN = append(result.ALPN, string(body[:size]))
				body = body[size:]
			}
		}
	}
	return result, nil
}

// StructuralKey intentionally excludes random GREASE and extension ordering,
// record lengths and optional padding. Inspect those separately in captures.
func (s Summary) StructuralKey() string {
	s.RecordSizes = nil
	s.HelloSize = 0
	s.CipherSuites = append([]uint16(nil), s.CipherSuites...)
	s.Extensions = append([]uint16(nil), s.Extensions...)
	sort.Slice(s.CipherSuites, func(i, j int) bool { return s.CipherSuites[i] < s.CipherSuites[j] })
	var extensions []uint16
	for _, v := range s.Extensions {
		if v != 21 {
			extensions = append(extensions, v)
		}
	}
	s.Extensions = extensions
	sort.Slice(s.Extensions, func(i, j int) bool { return s.Extensions[i] < s.Extensions[j] })
	parameters := make([]TransportParameter, 0, len(s.TransportParameters))
	for _, p := range s.TransportParameters {
		if p.ID < 27 || (p.ID-27)%31 != 0 {
			parameters = append(parameters, p)
		}
	}
	s.TransportParameters = parameters
	sort.Slice(s.TransportParameters, func(i, j int) bool { return s.TransportParameters[i].ID < s.TransportParameters[j].ID })
	data, _ := json.Marshal(s)
	return string(data)
}
