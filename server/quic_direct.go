package main

import (
	"atlant.local/protocol/quicreality"
	"atlant.local/protocol/realityauth"
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

const directMaxPending = 1024

type directAttempt struct {
	observer  quicreality.Observer
	packets   [][]byte
	bytes     int
	created   time.Time
	peer, ip  string
	admission *quicreality.Admission
}

type directQUICGate struct {
	inboundID        string
	identity         *ecdh.PrivateKey
	mu               sync.Mutex
	pending          map[string]*directAttempt
	perIP            map[string]int
	spent            map[[32]byte]int64
	lastSweep        time.Time
	validationCredit float64
	lastValidation   time.Time
}

func newDirectQUICGate() *directQUICGate {
	return newDirectQUICGateWithIdentity(serverStaticECDH)
}

func newDirectQUICGateWithIdentity(identity *ecdh.PrivateKey) *directQUICGate {
	return &directQUICGate{identity: identity, pending: make(map[string]*directAttempt), perIP: make(map[string]int), spent: make(map[[32]byte]int64), validationCredit: 256, lastValidation: time.Now()}
}

func directKey(peer string, dcid []byte) string { return peer + "\x00" + string(dcid) }

func (g *directQUICGate) removeLocked(key string) {
	if p := g.pending[key]; p != nil {
		g.perIP[p.ip]--
		if g.perIP[p.ip] == 0 {
			delete(g.perIP, p.ip)
		}
		delete(g.pending, key)
	}
}

func (g *directQUICGate) pruneLocked(now time.Time) {
	if now.Sub(g.lastSweep) < time.Second {
		return
	}
	g.lastSweep = now
	for k, p := range g.pending {
		if now.Sub(p.created) > 10*time.Second {
			g.removeLocked(k)
		}
	}
	for k, expires := range g.spent {
		if expires < now.Unix() {
			delete(g.spent, k)
		}
	}
}

func directCandidates(tag [4]byte) []realityauth.Candidate {
	records := usersStorage.GetUsersByTag(tag)
	if len(records) > 16 {
		return make([]realityauth.Candidate, 17)
	}
	var out []realityauth.Candidate
	for _, u := range records {
		if u != nil {
			key, err := hex.DecodeString(u.PBK)
			if err == nil && len(key) == 32 {
				out = append(out, realityauth.Candidate{Name: u.Name, Key: key})
			}
		}
	}
	return out
}

// The pending key includes the complete UDP tuple: a replay from another port
// cannot occupy the genuine client's assembly or consume its admission.
// Held packets are bounded and released only after the complete Hello is valid.
func (g *directQUICGate) accept(packet []byte, addr net.Addr) (packets [][]byte, admitted, held bool) {
	dcid, ok := quicreality.InitialID(packet)
	if !ok || addr == nil {
		return [][]byte{packet}, false, false
	}
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return [][]byte{packet}, false, false
	}
	key := directKey(addr.String(), dcid)
	now := time.Now()
	g.mu.Lock()
	g.pruneLocked(now)
	p := g.pending[key]
	if p == nil {
		if len(g.pending) >= directMaxPending || g.perIP[ip] >= 64 || len(g.spent) >= 65536 {
			g.mu.Unlock()
			return nil, false, true
		}
		p = &directAttempt{created: now, peer: addr.String(), ip: ip}
		g.pending[key] = p
		g.perIP[ip]++
	}
	if p.admission == nil {
		if len(p.packets) >= 16 || p.bytes+len(packet) > 24*1024 {
			packets = p.packets
			packets = append(packets, bytes.Clone(packet))
			g.removeLocked(key)
			g.mu.Unlock()
			return packets, false, false
		}
		p.packets = append(p.packets, bytes.Clone(packet))
		p.bytes += len(packet)
	}
	hello, err := p.observer.Feed(packet)
	if errors.Is(err, quicreality.ErrIncomplete) {
		g.mu.Unlock()
		return nil, false, true
	}
	if err != nil {
		packets = p.packets
		if len(packets) == 0 {
			packets = [][]byte{bytes.Clone(packet)}
		}
		g.removeLocked(key)
		g.mu.Unlock()
		return packets, false, false
	}
	if p.admission != nil {
		_, used := g.spent[p.admission.HelloHash]
		valid := !used && now.Unix() <= p.admission.Expires
		g.mu.Unlock()
		return [][]byte{packet}, valid, false
	}
	packets = p.packets
	// Bound expensive X25519/proof checks even when invalid complete Hellos
	// are immediately removed. UDP source addresses are not trusted yet.
	g.validationCredit += now.Sub(g.lastValidation).Seconds() * 256
	if g.validationCredit > 256 {
		g.validationCredit = 256
	}
	g.lastValidation = now
	if g.validationCredit < 1 {
		g.removeLocked(key)
		g.mu.Unlock()
		return nil, false, true
	}
	g.validationCredit--
	g.mu.Unlock()
	a, err := quicreality.VerifyHello(hello, g.identity, directCandidates, now)
	if err == nil && (!isUserAllowed(a.User) || !inboundUserAllowed(g.inboundID, a.User)) {
		err = quicreality.ErrAuthentication
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending[key] != p {
		return nil, false, true
	}
	if _, used := g.spent[a.HelloHash]; used {
		err = quicreality.ErrAuthentication
	}
	if err != nil {
		g.removeLocked(key)
		return packets, false, false
	}
	p.admission = &a
	p.packets = nil
	p.bytes = 0
	return packets, true, false
}

type directContextKey struct{}
type directContext struct {
	gate      *directQUICGate
	peer      string
	admission *quicreality.Admission
}

func (g *directQUICGate) connContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if !info.AddrVerified {
		return nil, errors.New("direct QUIC requires validated UDP source")
	}
	return context.WithValue(ctx, directContextKey{}, &directContext{gate: g, peer: info.RemoteAddr.String()}), nil
}

func (g *directQUICGate) tracer(ctx context.Context, _ bool, dcid quic.ConnectionID) qlogwriter.Trace {
	ref, _ := ctx.Value(directContextKey{}).(*directContext)
	if ref == nil {
		return nil
	}
	g.mu.Lock()
	p := g.pending[directKey(ref.peer, dcid.Bytes())]
	if p != nil && p.admission != nil {
		a := *p.admission
		ref.admission = &a
	}
	g.mu.Unlock()
	context.AfterFunc(ctx, func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		for k, p := range g.pending {
			if p.peer == ref.peer && ref.admission != nil && p.admission != nil && p.admission.HelloHash == ref.admission.HelloHash {
				g.removeLocked(k)
			}
		}
	})
	return nil
}

func directAdmission(ctx context.Context) (*quicreality.Admission, error) {
	ref, _ := ctx.Value(directContextKey{}).(*directContext)
	if ref == nil || ref.admission == nil {
		return nil, quicreality.ErrAuthentication
	}
	return ref.admission, nil
}

func commitDirectAdmission(conn *quic.Conn, user string) error {
	ref, _ := conn.Context().Value(directContextKey{}).(*directContext)
	if ref == nil || ref.admission == nil || ref.admission.User != user {
		return quicreality.ErrAuthentication
	}
	g := ref.gate
	if !inboundUserAllowed(g.inboundID, user) {
		return quicreality.ErrAuthentication
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked(time.Now())
	if _, exists := g.spent[ref.admission.HelloHash]; exists || len(g.spent) >= 65536 || time.Now().Unix() > ref.admission.Expires {
		return quicreality.ErrAuthentication
	}
	g.spent[ref.admission.HelloHash] = ref.admission.Expires
	return nil
}
