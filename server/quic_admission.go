package main

import (
	"atlant.local/protocol/quicadmission"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
)

var activeAdmission atomic.Pointer[admissionGate]

type admissionClaim struct {
	token    quicadmission.Token
	attempt  quicadmission.Attempt
	subject  string
	peer     string
	created  time.Time
	attached bool
	digest   [32]byte
}

type admissionGate struct {
	store   *quicadmission.Store
	mu      sync.Mutex
	pending map[string]*admissionClaim
}

type admissionContextKey struct{}
type admissionContext struct {
	peer     string
	claim    *admissionClaim
	gate     *admissionGate
	expected bool
}

func newAdmissionGate() (*admissionGate, error) {
	s, err := quicadmission.NewStore(quicadmission.Options{Capacity: 65536, PerSubject: 1024, TTL: 90 * time.Second})
	if err != nil {
		return nil, err
	}
	return &admissionGate{store: s, pending: make(map[string]*admissionClaim)}, nil
}

// Initial attempt binding covers canonical observed peer, version, original
// DCID and client SCID with explicit lengths. Header fields are untrusted;
// admission is only a resource gate, never proof or address validation.
func initialAdmissionFields(p []byte, addr net.Addr) (quicadmission.Token, quicadmission.Attempt, string, bool) {
	return initialAdmissionFieldsKnown(p, addr, nil)
}

func initialAdmissionFieldsKnown(p []byte, addr net.Addr, known *quicadmission.Token) (quicadmission.Token, quicadmission.Attempt, string, bool) {
	var token quicadmission.Token
	var attempt quicadmission.Attempt
	if addr == nil || len(p) < 1200 || p[0]&0xc0 != 0xc0 {
		return token, attempt, "", false
	}
	v := binary.BigEndian.Uint32(p[1:5])
	typ := (p[0] & 0x30) >> 4
	if !(v == 1 && typ == 0 || v == 0x6b3343cf && typ == 1) {
		return token, attempt, "", false
	}
	dcil := int(p[5])
	if dcil < 8 || dcil > 20 || len(p) < 7+dcil {
		return token, attempt, "", false
	}
	scil := int(p[6+dcil])
	if len(p) < 7+dcil+scil || (known == nil && scil != quicadmission.TokenSize) || (known != nil && scil != 0) {
		return token, attempt, "", false
	}
	if known != nil {
		token = *known
	} else {
		copy(token[:], p[7+dcil:7+dcil+scil])
	}
	h := sha256.New()
	peer := addr.String()
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(peer)))
	h.Write(size[:])
	h.Write([]byte(peer))
	h.Write(p[1:5])
	h.Write([]byte{byte(dcil)})
	h.Write(p[6 : 6+dcil])
	h.Write([]byte{byte(scil)})
	h.Write(token[:])
	copy(attempt[:], h.Sum(nil))
	return token, attempt, string(p[6 : 6+dcil]), true
}

func (g *admissionGate) admit(p []byte, addr net.Addr) bool {
	token, attempt, dcid, ok := initialAdmissionFields(p, addr)
	if cfg != nil && (cfg.WireVersion == 4 || cfg.WireVersion == 6) {
		registered, found := g.store.ResolvePacket(quicadmission.PacketDigest(p))
		if !found {
			return false
		}
		token, attempt, dcid, ok = initialAdmissionFieldsKnown(p, addr, &registered)
	}
	if !ok {
		return false
	}
	if cfg != nil && cfg.WireVersion == 6 {
		return g.inspectInitial(token, dcid, p)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if prior := g.pending[dcid]; prior != nil {
		if prior.attempt != attempt {
			return false
		}
		_, err := g.admitToken(token, attempt, p, addr)
		return err == nil
	}
	// No O(N) sweep on arbitrary unknown packets. Capacity is fixed and the
	// bounded sweeper below runs independently of packet processing.
	if len(g.pending) >= 65536 {
		return false
	}
	subject, err := g.admitToken(token, attempt, p, addr)
	if err != nil {
		return false
	}
	g.pending[dcid] = &admissionClaim{token: token, attempt: attempt, subject: subject, peer: addr.String(), created: time.Now()}
	return true
}

// A copied Initial may cause a standard Retry, but must not reserve the user's
// token. Claim only after quic-go validates the Retry token against IP AND port.
func (g *admissionGate) inspectInitial(token quicadmission.Token, dcid string, packet []byte) bool {
	digest := quicadmission.PacketDigest(packet)
	subject, err := g.store.InspectPacket(token, digest)
	if err != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if prior := g.pending[dcid]; prior != nil {
		return prior.token == token
	}
	if len(g.pending) >= 65536 {
		return false
	}
	g.pending[dcid] = &admissionClaim{token: token, subject: subject, digest: digest, created: time.Now()}
	return true
}

func (g *admissionGate) admitToken(token quicadmission.Token, attempt quicadmission.Attempt, packet []byte, addr net.Addr) (string, error) {
	if cfg != nil && cfg.WireVersion == 6 {
		peerIP, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", quicadmission.ErrRejected
		}
		return g.store.AdmitPacketFromPeer(token, attempt, quicadmission.PacketDigest(packet), peerIP)
	}
	if cfg != nil && (cfg.WireVersion == 4 || cfg.WireVersion == 6) {
		return g.store.AdmitPacket(token, attempt, quicadmission.PacketDigest(packet))
	}
	return g.store.Admit(token, attempt)
}

func (g *admissionGate) prune() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for dcid, claim := range g.pending {
		if time.Since(claim.created) > 90*time.Second {
			_ = g.store.Retire(claim.token, claim.attempt)
			delete(g.pending, dcid)
		}
	}
}

func (g *admissionGate) connContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if cfg.WireVersion == 6 && !info.AddrVerified {
		return nil, errors.New("wire6 requires QUIC address validation")
	}
	return context.WithValue(ctx, admissionContextKey{}, &admissionContext{peer: info.RemoteAddr.String(), gate: g, expected: !cfg.LegacyWire}), nil
}

// quic-go v0.63.0 supplies original DCID here before constructing the Conn.
// This is an association hook only: no qlog file or secret-bearing trace.
func (g *admissionGate) tracer(ctx context.Context, _ bool, dcid quic.ConnectionID) qlogwriter.Trace {
	ref, _ := ctx.Value(admissionContextKey{}).(*admissionContext)
	if ref == nil {
		return nil
	}
	g.mu.Lock()
	claim := g.pending[string(dcid.Bytes())]
	if claim != nil {
		ref.expected = true
	}
	if cfg.WireVersion == 6 && claim != nil && !claim.attached {
		attempt := sha256.Sum256([]byte("atlant/quic/wire6/validated-peer\x00" + ref.peer + "\x00" + string(dcid.Bytes())))
		if _, err := g.store.AdmitPacket(claim.token, attempt, claim.digest); err == nil {
			claim.attempt, claim.peer = attempt, ref.peer
		}
	}
	if claim != nil && !claim.attached && claim.peer == ref.peer {
		claim.attached = true
		ref.claim = claim
	}
	g.mu.Unlock()
	if ref.claim != nil {
		context.AfterFunc(ctx, func() {
			_ = g.store.Retire(claim.token, claim.attempt)
			g.mu.Lock()
			if g.pending[string(dcid.Bytes())] == claim {
				delete(g.pending, string(dcid.Bytes()))
			}
			g.mu.Unlock()
		})
	}
	return nil
}

func commitAdmission(conn *quic.Conn, subject string) error {
	_, direct := conn.Context().Value(directContextKey{}).(*directContext)
	if direct || cfg.WireVersion == 7 {
		return commitDirectAdmission(conn, subject)
	}
	ref, _ := conn.Context().Value(admissionContextKey{}).(*admissionContext)
	if ref == nil {
		return nil
	}
	if ref.claim == nil {
		if ref.expected {
			return errors.New("admission association missing")
		}
		return nil
	}
	return ref.gate.store.Commit(ref.claim.token, ref.claim.attempt, subject)
}

func serveRealityAdmission(stream net.Conn, name string, version int) {
	defer stream.Close()
	g := activeAdmission.Load()
	if g == nil || version != 3 || !isUserAllowed(name) {
		return
	}
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	var request [3]byte
	if _, err := io.ReadFull(stream, request[:]); err != nil || request != [3]byte{} {
		return
	}
	batch, err := g.store.Issue(name, quicadmission.BootstrapBatchSize)
	if err != nil {
		return
	}
	_ = quicadmission.WriteBatch(stream, batch)
}

func serveBoundRealityAdmission(stream net.Conn, name string, version int) {
	defer stream.Close()
	g := activeAdmission.Load()
	if g == nil || (version != 4 && version != 6) || cfg.WireVersion != version || !isUserAllowed(name) {
		return
	}
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	var request [3]byte
	if _, err := io.ReadFull(stream, request[:]); err != nil || request != [3]byte{} {
		return
	}
	var batch quicadmission.Batch
	var err error
	if version == 6 {
		// TCP and UDP may have different public egress addresses. The registered
		// Initial plus a full-tuple Retry establishes the UDP source separately.
		batch, err = g.store.IssueBound(name, quicadmission.Wire6BatchSize)
	} else {
		batch, err = g.store.IssueBound(name, quicadmission.BoundBatchSize)
	}
	if err != nil {
		return
	}
	if err := quicadmission.WriteBatchVersion(stream, batch, byte(version)); err != nil {
		return
	}
	if version == 6 {
		_ = quicadmission.ServeBoundFlightRegistrations(stream, g.store, name, batch)
		return
	}
	_ = quicadmission.ServeBoundRegistrations(stream, g.store, name, batch)
}
