// Package quicadmission manages wire3's one-attempt admission tokens.
// Admission limits session setup; TLS-bound peer authentication still decides
// whether a connection may proxy traffic. Legacy wire2 uses a separate CID codec.
package quicadmission

import (
	"container/heap"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const TokenSize = 20
const MaxBatch = 256

// Token is opaque random admission material. No username, timestamp, version
// marker, counter or public decoding key is encoded in its bytes.
type Token [TokenSize]byte
type Attempt [32]byte

var (
	ErrRejected      = errors.New("admission rejected")
	ErrCapacity      = errors.New("admission capacity exhausted")
	ErrOptions       = errors.New("invalid admission options")
	ErrEntropy       = errors.New("could not issue unique admission material")
	ErrPoolExhausted = errors.New("CID pool exhausted; authenticated replenishment required")
)

// String prevents ordinary diagnostic formatting from exposing a bearer token.
func (Token) String() string { return "[redacted admission token]" }

func ParseToken(value []byte) (Token, error) {
	var token Token
	if len(value) != TokenSize {
		return token, ErrRejected
	}
	copy(token[:], value)
	return token, nil
}

type Options struct {
	Capacity   int
	PerSubject int
	TTL        time.Duration
}

func DefaultOptions() Options {
	return Options{Capacity: 65536, PerSubject: 256, TTL: 15 * time.Minute}
}

type Batch struct {
	Tokens  []Token
	Expires time.Time
}

type state uint8

const (
	issued state = iota
	claimed
	spent
)

type entry struct {
	digest  [32]byte
	subject string
	expires time.Time
	attempt Attempt
	state   state
	index   int
	bound   bool
	packets map[[32]byte]struct{}
	peerIP  string
}

type expiryQueue []*entry

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].expires.Before(q[j].expires) }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i]; q[i].index = i; q[j].index = j }
func (q *expiryQueue) Push(value any)    { e := value.(*entry); e.index = len(*q); *q = append(*q, e) }
func (q *expiryQueue) Pop() any {
	old := *q
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*q = old[:len(old)-1]
	e.index = -1
	return e
}

type Store struct {
	mu             sync.Mutex
	options        Options
	entries        map[[32]byte]*entry
	subjects       map[string]int
	expiry         expiryQueue
	now            func() time.Time
	random         io.Reader
	packetCount    int
	registered     map[[32]byte]Token
	packetSubjects map[string]int
}

func NewStore(options Options) (*Store, error) {
	if options.Capacity < 1 || options.Capacity > 1<<20 || options.PerSubject < 1 || options.PerSubject > options.Capacity || options.TTL < time.Second || options.TTL > time.Hour {
		return nil, ErrOptions
	}
	return &Store{options: options, entries: make(map[[32]byte]*entry), subjects: make(map[string]int), registered: make(map[[32]byte]Token), packetSubjects: make(map[string]int), now: time.Now, random: rand.Reader}, nil
}

// Issue MUST only be called after independent authentication and authorization.
// Entropy generation happens outside the store lock; the whole batch either
// commits or fails. Slots include spent tombstones until expiry: no live entry
// is evicted to make room for an attacker. Wire3 stores token digests; wire4
// registrations additionally keep a private token handle, never sent over UDP.
func (s *Store) Issue(subject string, count int) (Batch, error) {
	return s.issue(subject, count, false)
}

func (s *Store) IssueBound(subject string, count int) (Batch, error) {
	return s.issue(subject, count, true)
}

// IssueBoundForPeer restricts wire5 admission to the authenticated carrier's
// public IP. NAT may change ports; a different public IP requires rebootstrap.
func (s *Store) IssueBoundForPeer(subject string, count int, peerIP string) (Batch, error) {
	ip, err := netip.ParseAddr(peerIP)
	if err != nil || !ip.IsValid() || ip.Zone() != "" {
		return Batch{}, ErrOptions
	}
	return s.issueForPeer(subject, count, true, ip.Unmap().String())
}

func (s *Store) issue(subject string, count int, bound bool) (Batch, error) {
	return s.issueForPeer(subject, count, bound, "")
}

func (s *Store) issueForPeer(subject string, count int, bound bool, peerIP string) (Batch, error) {
	if subject == "" || len(subject) > 256 || count < 1 || count > MaxBatch {
		return Batch{}, ErrOptions
	}
	tokens := make([]Token, count)
	digests := make([][32]byte, count)
	unique := make(map[[32]byte]struct{}, count)
	for i := range tokens {
		if _, err := io.ReadFull(s.random, tokens[i][:]); err != nil {
			return Batch{}, ErrEntropy
		}
		digests[i] = sha256.Sum256(tokens[i][:])
		if _, exists := unique[digests[i]]; exists {
			return Batch{}, ErrEntropy
		}
		unique[digests[i]] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.prune(now)
	if count > s.options.Capacity-len(s.entries) || count > s.options.PerSubject-s.subjects[subject] {
		return Batch{}, ErrCapacity
	}
	for _, digest := range digests {
		if _, exists := s.entries[digest]; exists {
			return Batch{}, ErrEntropy
		}
	}
	expires := now.Add(s.options.TTL)
	ownedSubject := strings.Clone(subject)
	for _, digest := range digests {
		e := &entry{digest: digest, subject: ownedSubject, expires: expires, bound: bound, peerIP: peerIP}
		s.entries[digest] = e
		heap.Push(&s.expiry, e)
	}
	s.subjects[ownedSubject] += count
	return Batch{Tokens: tokens, Expires: expires}, nil
}

func (s *Store) drop(e *entry) {
	s.clearPackets(e)
	delete(s.entries, e.digest)
	heap.Remove(&s.expiry, e.index)
	s.subjects[e.subject]--
	if s.subjects[e.subject] == 0 {
		delete(s.subjects, e.subject)
	}
}
func (s *Store) prune(now time.Time) {
	for len(s.expiry) > 0 && !now.Before(s.expiry[0].expires) {
		s.drop(s.expiry[0])
	}
}
func (s *Store) lookup(token Token) *entry {
	e := s.entries[sha256.Sum256(token[:])]
	if e != nil && !s.now().Before(e.expires) {
		s.drop(e)
		return nil
	}
	return e
}

// Admit is only pre-TLS resource admission, NEVER authorization to proxy data.
// Unknown tokens perform one hash/map lookup without allocating a session or
// scanning users. Attempt is a server-side attempt binding (see README), not
// an identity/credential supplied by a client. Retransmissions can reuse it.
func (s *Store) Admit(token Token, attempt Attempt) (string, error) {
	return s.admit(token, attempt, nil, "")
}

func (s *Store) AdmitPacket(token Token, attempt Attempt, digest [32]byte) (string, error) {
	return s.admit(token, attempt, &digest, "")
}

func (s *Store) AdmitPacketFromPeer(token Token, attempt Attempt, digest [32]byte, peerIP string) (string, error) {
	return s.admit(token, attempt, &digest, peerIP)
}

// InspectPacket performs the private-registration check without claiming an
// attempt. Wire5 must validate the UDP source with QUIC Retry before claiming.
func (s *Store) InspectPacket(token Token, digest [32]byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lookup(token)
	if e == nil || !e.bound || e.state == spent || e.peerIP != "" {
		return "", ErrRejected
	}
	if _, ok := e.packets[digest]; !ok {
		return "", ErrRejected
	}
	return e.subject, nil
}

func (s *Store) admit(token Token, attempt Attempt, digest *[32]byte, peerIP string) (string, error) {
	if attempt == (Attempt{}) {
		return "", ErrRejected
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lookup(token)
	if e == nil || e.state == spent {
		return "", ErrRejected
	}
	if e.peerIP != "" {
		ip, err := netip.ParseAddr(peerIP)
		if err != nil || ip.Unmap().String() != e.peerIP {
			return "", ErrRejected
		}
	}
	if e.bound != (digest != nil) {
		return "", ErrRejected
	}
	if digest != nil {
		if _, ok := e.packets[*digest]; !ok {
			return "", ErrRejected
		}
	}
	if e.state == claimed && e.attempt != attempt {
		return "", ErrRejected
	}
	if e.state == issued {
		e.state = claimed
		e.attempt = attempt
	}
	return e.subject, nil
}

// Commit is called only AFTER TLS-exporter-bound peer authentication succeeds.
// The authenticated subject must match the private admission record. A wrong
// subject consumes rather than releases the token; it cannot become reusable.
func (s *Store) Commit(token Token, attempt Attempt, authenticatedSubject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lookup(token)
	if e == nil || e.state != claimed || e.attempt != attempt {
		return ErrRejected
	}
	e.state = spent
	s.clearPackets(e)
	if e.subject != authenticatedSubject {
		return ErrRejected
	}
	return nil
}

// Retire burns a failed attempt. Never release a publicly observed token back
// into an issuance pool. Repeated calls and wrong attempts are rejected.
func (s *Store) Retire(token Token, attempt Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lookup(token)
	if e == nil || e.state != claimed || e.attempt != attempt {
		return ErrRejected
	}
	e.state = spent
	s.clearPackets(e)
	return nil
}

// RevokeSubject is an administrative operation, not an unauthenticated fast
// path. Remove heap items too, so repeated revoke/issue cannot grow the queue.
func (s *Store) RevokeSubject(subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.subject == subject {
			s.drop(e)
		}
	}
}

// RevokeAll is administrative, e.g. restore or explicit all-session revocation.
func (s *Store) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.entries)
	clear(s.subjects)
	clear(s.expiry)
	s.expiry = s.expiry[:0]
	s.packetCount = 0
	clear(s.registered)
	clear(s.packetSubjects)
}

const MaxPacketsPerToken = 64
const maxRegisteredPackets = 65536
const maxPacketsPerSubject = 4096

func (s *Store) clearPackets(e *entry) {
	s.packetSubjects[e.subject] -= len(e.packets)
	if s.packetSubjects[e.subject] == 0 {
		delete(s.packetSubjects, e.subject)
	}
	for digest := range e.packets {
		delete(s.registered, digest)
	}
	s.packetCount -= len(e.packets)
	e.packets = nil
}

// RegisterPacket is reachable only through an authenticated wire4 REALITY
// stream. Untrusted UDP never allocates packet registrations or reassembly.
func (s *Store) RegisterPacket(subject string, token Token, digest [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.lookup(token)
	if e == nil || !e.bound || e.state == spent || e.subject != subject {
		return ErrRejected
	}
	if _, ok := e.packets[digest]; ok {
		return nil
	}
	if _, exists := s.registered[digest]; exists {
		return ErrRejected
	}
	if len(e.packets) >= MaxPacketsPerToken || s.packetCount >= maxRegisteredPackets || s.packetSubjects[e.subject] >= maxPacketsPerSubject {
		return ErrCapacity
	}
	if e.packets == nil {
		e.packets = make(map[[32]byte]struct{})
	}
	e.packets[digest] = struct{}{}
	s.registered[digest] = token
	s.packetCount++
	s.packetSubjects[e.subject]++
	return nil
}

// ResolvePacket exposes admission material only to the private UDP gate. In
// wire4 the token travels solely inside REALITY, never in a public QUIC CID.
func (s *Store) ResolvePacket(digest [32]byte) (Token, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.registered[digest]
	if !ok {
		return Token{}, false
	}
	e := s.lookup(token)
	if e == nil || e.state == spent {
		return Token{}, false
	}
	return token, true
}

// Counts includes expired entries until an authenticated issuance/lookup prunes
// them. In particular, invalid traffic does not trigger an O(N) garbage sweep.
func (s *Store) Counts() (tokens, subjects int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries), len(s.subjects)
}
