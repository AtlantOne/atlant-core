// Package quicaudit observes public QUIC Initial metadata. It is a bounded,
// offline audit helper, not an authentication parser or a traffic classifier.
package quicaudit

import (
	"atlant.local/protocol/tlsaudit"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrPacket     = errors.New("invalid or unsupported client Initial")
	ErrIncomplete = errors.New("more client Initial CRYPTO data required")
)

const maxCrypto = 64 << 10

type Summary struct {
	Version       uint32           `json:"version"`
	DCIDLength    int              `json:"dcid_length"`
	SCIDLength    int              `json:"scid_length"`
	DatagramSizes []int            `json:"datagram_sizes"`
	PacketNumbers []uint64         `json:"packet_numbers"`
	ClientHello   tlsaudit.Summary `json:"client_hello"`
}

// Observer is owned by one capture goroutine and one Initial attempt. It never
// exports raw CIDs, tickets, SessionID, SNI, keys or application data.
type Observer struct {
	dcid    []byte
	scid    []byte
	next    uint64
	crypto  [maxCrypto]byte
	seen    [maxCrypto]bool
	summary Summary
}

func expand(secret []byte, label string, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	label = "tls13 " + label
	info = append(info, byte(len(label)))
	info = append(info, []byte(label)...)
	info = append(info, 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	return out
}

func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte, err error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	prefix := "quic"
	if version == 0x6b3343cf {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		prefix = "quicv2"
	} else if version != 1 {
		return nil, nil, nil, ErrPacket
	}
	secret := expand(hkdf.Extract(sha256.New, dcid, salt), "client in", 32)
	return expand(secret, prefix+" key", 16), expand(secret, prefix+" iv", 12), expand(secret, prefix+" hp", 16), nil
}

func varint(p *[]byte) (uint64, bool) {
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

func decode(data []byte, expected uint64) (version uint32, dcid, scid, plain []byte, pn uint64, err error) {
	fail := func() (uint32, []byte, []byte, []byte, uint64, error) { return 0, nil, nil, nil, 0, ErrPacket }
	if len(data) < 7 || len(data) > 65535 || data[0]&0xc0 != 0xc0 {
		return fail()
	}
	version = binary.BigEndian.Uint32(data[1:5])
	typ := (data[0] >> 4) & 3
	if !(version == 1 && typ == 0 || version == 0x6b3343cf && typ == 1) {
		return fail()
	}
	n := int(data[5])
	if n < 1 || n > 20 || len(data) < 7+n {
		return fail()
	}
	dcid = data[6 : 6+n]
	m := int(data[6+n])
	if m > 20 || len(data) < 7+n+m {
		return fail()
	}
	scid = data[7+n : 7+n+m]
	p := data[7+n+m:]
	tokenSize, ok := varint(&p)
	if !ok || tokenSize > uint64(len(p)) {
		return fail()
	}
	p = p[int(tokenSize):]
	length, ok := varint(&p)
	if !ok || length > uint64(len(p)) {
		return fail()
	}
	pnOffset := len(data) - len(p)
	end := pnOffset + int(length)
	if pnOffset+20 > end {
		return fail()
	}
	key, iv, hp, err := initialKeys(version, dcid)
	if err != nil {
		return fail()
	}
	protection, _ := aes.NewCipher(hp)
	var mask [16]byte
	protection.Encrypt(mask[:], data[pnOffset+4:pnOffset+20])
	header := append([]byte(nil), data[:pnOffset+4]...)
	header[0] ^= mask[0] & 0x0f
	if header[0]&0x0c != 0 {
		return fail()
	}
	pnLen := int(header[0]&3) + 1
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}
	window := uint64(1) << (8 * pnLen)
	candidate := expected&^(window-1) | pn
	if candidate+window/2 <= expected && candidate+window < 1<<62 {
		candidate += window
	} else if candidate > expected+window/2 && candidate >= window {
		candidate -= window
	}
	pn = candidate
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	for i := 0; i < 8; i++ {
		iv[11-i] ^= byte(pn >> (8 * i))
	}
	header = header[:pnOffset+pnLen]
	plain, err = aead.Open(nil, iv, data[pnOffset+pnLen:end], header)
	if err != nil {
		return fail()
	}
	return version, dcid, scid, plain, pn, nil
}

func (o *Observer) frames(p []byte) error {
	for len(p) > 0 {
		typ, ok := varint(&p)
		if !ok {
			return ErrPacket
		}
		switch typ {
		case 0, 1:
		case 2, 3:
			for i := 0; i < 2; i++ {
				if _, ok := varint(&p); !ok {
					return ErrPacket
				}
			}
			ranges, ok := varint(&p)
			if !ok || ranges > 256 {
				return ErrPacket
			}
			if _, ok := varint(&p); !ok {
				return ErrPacket
			}
			for i := uint64(0); i < 2*ranges; i++ {
				if _, ok := varint(&p); !ok {
					return ErrPacket
				}
			}
			if typ == 3 {
				for i := 0; i < 3; i++ {
					if _, ok := varint(&p); !ok {
						return ErrPacket
					}
				}
			}
		case 6:
			offset, ok := varint(&p)
			if !ok {
				return ErrPacket
			}
			size, ok := varint(&p)
			if !ok || size > uint64(len(p)) || offset > maxCrypto || size > maxCrypto-offset {
				return ErrPacket
			}
			for i, b := range p[:int(size)] {
				at := int(offset) + i
				if o.seen[at] && o.crypto[at] != b {
					return ErrPacket
				}
				o.crypto[at], o.seen[at] = b, true
			}
			p = p[int(size):]
		default:
			return ErrPacket
		}
	}
	return nil
}

func (o *Observer) Observe(datagram []byte) (Summary, error) {
	if len(o.summary.PacketNumbers) >= 1024 {
		return Summary{}, ErrPacket
	}
	version, dcid, scid, plain, pn, err := decode(datagram, o.next)
	if err != nil {
		return Summary{}, err
	}
	if o.dcid != nil && (!bytes.Equal(dcid, o.dcid) || !bytes.Equal(scid, o.scid) || version != o.summary.Version) {
		return Summary{}, ErrPacket
	}
	if o.dcid == nil {
		o.dcid = append([]byte(nil), dcid...)
		o.scid = append([]byte(nil), scid...)
		o.summary.Version = version
		o.summary.DCIDLength = len(dcid)
		o.summary.SCIDLength = len(scid)
	}
	if pn >= o.next {
		o.next = pn + 1
	}
	if err := o.frames(plain); err != nil {
		return Summary{}, err
	}
	o.summary.DatagramSizes = append(o.summary.DatagramSizes, len(datagram))
	o.summary.PacketNumbers = append(o.summary.PacketNumbers, pn)
	for i := 0; i < 4; i++ {
		if !o.seen[i] {
			return Summary{}, ErrIncomplete
		}
	}
	size := 4 + (int(o.crypto[1])<<16 | int(o.crypto[2])<<8 | int(o.crypto[3]))
	if o.crypto[0] != 1 || size > maxCrypto {
		return Summary{}, ErrPacket
	}
	for i := 4; i < size; i++ {
		if !o.seen[i] {
			return Summary{}, ErrIncomplete
		}
	}
	var records []byte
	for p := o.crypto[:size]; len(p) > 0; {
		n := len(p)
		if n > 16384 {
			n = 16384
		}
		records = append(records, 0x16, 3, 3, byte(n>>8), byte(n))
		records = append(records, p[:n]...)
		p = p[n:]
	}
	o.summary.ClientHello, err = tlsaudit.Summarize(records)
	if err != nil {
		return Summary{}, err
	}
	o.summary.ClientHello.RecordSizes = nil // QUIC CRYPTO is not a TLS record stream.
	return o.summary, nil
}
