package main

import (
	"atlant.local/protocol/quicpeer"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	lastAuthorizedUser atomic.Pointer[string]
	usedDCIDsMu        sync.Mutex
	usedDCIDs          = make(map[string]time.Time)
)

const maxQUICReplayEntries = 65536

// Never evict live replay records to admit new ones: fail closed under pressure.
func rememberQUICInitial(key string, now time.Time) bool {
	usedDCIDsMu.Lock()
	defer usedDCIDsMu.Unlock()
	if _, exists := usedDCIDs[key]; exists || len(usedDCIDs) >= maxQUICReplayEntries {
		return false
	}
	usedDCIDs[key] = now
	return true
}

func cleanupQUICReplayCache(now time.Time) {
	usedDCIDsMu.Lock()
	defer usedDCIDsMu.Unlock()
	cutoff := now.Add(-15 * time.Minute)
	for key, seen := range usedDCIDs {
		if seen.Before(cutoff) {
			delete(usedDCIDs, key)
		}
	}
}

func setLastAuthorizedUser(u string) {
	lastAuthorizedUser.Store(&u)
}

func getLastAuthorizedUser() string {
	if p := lastAuthorizedUser.Load(); p != nil {
		return *p
	}
	return ""
}

func init() {
	// Periodic cleanup of spent DCID cache
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			cleanupQUICReplayCache(time.Now())
			// Keep the full replay retention even under pressure. A timestamp
			// accepted up to 180s in the future can remain valid for another 180s;
			// evicting after only 3 minutes would reopen that replay window.
		}
	}()
}

// generateClientDCID generates client Destination Connection ID bound to SCID:
// [4B Masked Timestamp] + [4B Nonce] + [8B HMAC] = 16 bytes
func generateClientDCID(secretKey []byte, scid []byte) []byte {
	dcid := make([]byte, 16)
	ts := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(dcid[0:4], ts)
	_, _ = rand.Read(dcid[4:8]) // 4-byte random nonce

	mask := sha256.Sum256(append(secretKey, dcid[4:8]...))
	for i := 0; i < 4; i++ {
		dcid[i] ^= mask[i]
	}

	mac := hmac.New(sha256.New, secretKey)
	mac.Write(dcid[0:8])
	if len(scid) > 0 {
		mac.Write(scid)
	}
	tag := mac.Sum(nil)[:8]
	copy(dcid[8:16], tag)
	return dcid
}

var userPBKCache sync.Map

func invalidateUserPBKCache(name string) {
	userPBKCache.Delete(name)
}

func getCachedUserPBKBytes(u *userRecord) []byte {
	if val, ok := userPBKCache.Load(u.Name); ok {
		return val.([]byte)
	}
	if b, err := hex.DecodeString(u.PBK); err == nil && len(b) > 0 {
		userPBKCache.Store(u.Name, b)
		return b
	}
	return nil
}

// validateQUICInitial validates incoming QUIC Initial packet (RFC 9000) with SCID binding and anti-replay.
func validateQUICInitial(packet []byte, defaultSecretKey []byte) (bool, string) {
	// RFC 9000 14.1: Initial packet must be at least 1200 bytes
	if len(packet) < 1200 {
		return false, ""
	}

	firstByte := packet[0]
	// Check Long Header bit (bit 7) and fixed bit (bit 6)
	if (firstByte&0x80) == 0 || (firstByte&0x40) == 0 {
		log.Printf("[QUIC-AUTH-DEBUG] Rejected: not long header or fixed bit not set: 0x%02x", firstByte)
		return false, ""
	}

	// QUIC v2 changes the long-header packet type mapping.
	packetType := (firstByte & 0x30) >> 4
	version := binary.BigEndian.Uint32(packet[1:5])
	if !((version == 1 && packetType == 0) || (version == 0x6b3343cf && packetType == 1)) {
		log.Printf("[QUIC-AUTH-DEBUG] Rejected: not Initial packet type: 0x%02x", packetType)
		return false, ""
	}

	// Long Header:
	// 1 byte Flags, 4 bytes Version, 1 byte DCIL
	if len(packet) < 7 {
		log.Printf("[QUIC-AUTH-DEBUG] Rejected: packet too short for header: %d", len(packet))
		return false, ""
	}
	dcil := int(packet[5])
	if dcil > 20 || len(packet) < 6+dcil+1 {
		return false, ""
	}
	dcid := packet[6 : 6+dcil]

	// Extract SCID from Long Header
	scilOffset := 6 + dcil
	scil := int(packet[scilOffset])
	if scil > 20 || len(packet) < scilOffset+1+scil {
		return false, ""
	}
	scid := packet[scilOffset+1 : scilOffset+1+scil]
	now := int64(time.Now().Unix())

	authenticated := false
	authenticatedUser := ""
	authKeyForBinding := string(dcid)

	// Primary: Verify SCID (Native ConnectionIDGenerator RFC-compliant method)
	if scil == 16 {
		// Historical 16-byte codec, not wire3 admission. Its public mask
		// permits tag recovery, so it remains a compatibility path only.
		hmacTag := scid[8:16]
		mask := sha256.Sum256(append([]byte("atlant-quic-v3"), hmacTag...))
		var uTag [4]byte
		for i := 0; i < 4; i++ {
			uTag[i] = scid[i] ^ mask[i]
		}

		candidates := usersStorage.GetUsersByTag(uTag)
		for _, u := range candidates {
			if u == nil {
				continue
			}
			pbkBytes, err := hex.DecodeString(u.PBK)
			if err != nil || len(pbkBytes) == 0 {
				continue
			}
			unmaskedTS := binary.BigEndian.Uint32(scid[4:8]) ^ binary.BigEndian.Uint32(mask[4:8])
			delta := now - int64(unmaskedTS)
			if delta < -180 || delta > 180 {
				continue
			}
			var tsBytes [4]byte
			binary.BigEndian.PutUint32(tsBytes[:], unmaskedTS)

			mac := hmac.New(sha256.New, pbkBytes)
			mac.Write([]byte("atlant-quic-scid16"))
			mac.Write(uTag[:])
			mac.Write(tsBytes[:])
			expected := mac.Sum(nil)[:8]
			if hmac.Equal(hmacTag, expected) {
				authenticated = true
				authenticatedUser = u.Name
				authKeyForBinding = string(scid)
				break
			}
		}
	} else if scil == 20 {
		if userTag, ok := quicpeer.CIDUserTag(scid); ok {
			for _, user := range usersStorage.GetUsersByTag(userTag) {
				if user != nil && quicpeer.VerifyCID(scid, parsePBKBytes(user.PBK), time.Unix(now, 0)) {
					authenticated = true
					authenticatedUser = user.Name
					authKeyForBinding = string(scid)
					break
				}
			}
		}
	} else if scil >= 16 {
		// Legacy V2 / 16-byte fallback
		checkSCIDWithKey := func(key []byte) bool {
			// Masked V3 verification
			mask := sha256.Sum256(append(key, scid[4:8]...))
			unmaskedTS := binary.BigEndian.Uint32(scid[0:4]) ^ binary.BigEndian.Uint32(mask[:4])
			delta := now - int64(unmaskedTS)
			if delta >= -180 && delta <= 180 {
				mac := hmac.New(sha256.New, key)
				mac.Write(scid[0:8])
				expected := mac.Sum(nil)[:8]
				if hmac.Equal(scid[8:16], expected) {
					return true
				}
			}
			// Legacy unmasked verification fallback
			legacyTS := int64(binary.BigEndian.Uint32(scid[0:4]))
			deltaLeg := now - legacyTS
			if deltaLeg >= -180 && deltaLeg <= 180 {
				mac := hmac.New(sha256.New, key)
				mac.Write(scid[0:8])
				expected := mac.Sum(nil)[:8]
				if hmac.Equal(scid[8:16], expected) {
					return true
				}
			}
			return false
		}

		candidates := getUserAuthCandidates()
		for _, u := range candidates {
			if checkSCIDWithKey(u.PBKBytes) {
				authenticated = true
				if authenticatedUser == "" {
					authenticatedUser = u.Name
				}
				break
			}
		}
		if !authenticated && len(defaultSecretKey) > 0 {
			if checkSCIDWithKey(defaultSecretKey) {
				authenticated = true
				if authenticatedUser == "" {
					authenticatedUser = "default"
				}
			}
		}
		if authenticated {
			authKeyForBinding = string(scid)
		}
	}

	// Secondary / Fallback: Verify DCID
	if !authenticated && dcil >= 16 {
		checkDCIDWithKey := func(key []byte) bool {
			// Masked V3 verification
			mask := sha256.Sum256(append(key, dcid[4:8]...))
			unmaskedTS := binary.BigEndian.Uint32(dcid[0:4]) ^ binary.BigEndian.Uint32(mask[:4])
			delta := now - int64(unmaskedTS)
			if delta >= -180 && delta <= 180 {
				mac := hmac.New(sha256.New, key)
				mac.Write(dcid[0:8])
				mac.Write(scid)
				expected := mac.Sum(nil)[:8]
				if hmac.Equal(dcid[8:16], expected) {
					return true
				}
			}
			// Legacy unmasked verification fallback
			legacyTS := int64(binary.BigEndian.Uint32(dcid[0:4]))
			deltaLeg := now - legacyTS
			if deltaLeg >= -180 && deltaLeg <= 180 {
				mac := hmac.New(sha256.New, key)
				mac.Write(dcid[0:8])
				mac.Write(scid)
				expected := mac.Sum(nil)[:8]
				if hmac.Equal(dcid[8:16], expected) {
					return true
				}
			}
			return false
		}

		candidates := getUserAuthCandidates()
		for _, u := range candidates {
			if checkDCIDWithKey(u.PBKBytes) {
				authenticated = true
				if authenticatedUser == "" {
					authenticatedUser = u.Name
				}
				break
			}
		}
		if !authenticated && len(defaultSecretKey) > 0 {
			if checkDCIDWithKey(defaultSecretKey) {
				authenticated = true
				if authenticatedUser == "" {
					authenticatedUser = "default"
				}
			}
		}
		if authenticated {
			authKeyForBinding = string(dcid)
		}
	}

	if !authenticated {
		usersMu.RLock()
		count := len(usersDB.Users)
		usersMu.RUnlock()
		log.Printf("[QUIC-AUTH-DEBUG] Packet not authenticated (len(users)=%d)", count)
		return false, ""
	}

	if !isUserAllowed(authenticatedUser) {
		log.Printf("[QUIC-AUTH] User '%s' is rejected (disabled, expired, or quota reached)", authenticatedUser)
		return false, ""
	}

	// Anti-replay check
	if !rememberQUICInitial(authKeyForBinding, time.Now()) {
		return false, ""
	}

	// Bind client session IP and Connection ID to authenticated identity (preventing userTag spoofing)
	bindAuthenticatedUser(authKeyForBinding, authenticatedUser)
	return true, authenticatedUser
}

type authUserEntry struct {
	user     string
	expireAt time.Time
}

var (
	connAuthUserMu      sync.RWMutex
	connAuthUsers       = make(map[string]authUserEntry) // DCID/IP -> {username, expireAt}
	connAuthLastCleanup time.Time
)

func bindAuthenticatedUser(key string, user string) {
	connAuthUserMu.Lock()
	connAuthUsers[key] = authUserEntry{
		user:     user,
		expireAt: time.Now().Add(10 * time.Minute),
	}
	// Garbage collect expired entries periodically when map exceeds 500 items
	if len(connAuthUsers) > 500 && time.Since(connAuthLastCleanup) >= time.Minute {
		now := time.Now()
		connAuthLastCleanup = now
		for k, v := range connAuthUsers {
			if now.After(v.expireAt) {
				delete(connAuthUsers, k)
			}
		}
	}
	connAuthUserMu.Unlock()
}

func getBoundAuthenticatedUser(key string) string {
	connAuthUserMu.RLock()
	defer connAuthUserMu.RUnlock()
	entry, ok := connAuthUsers[key]
	if !ok || time.Now().After(entry.expireAt) {
		return ""
	}
	return entry.user
}

// User-space Decoy-NAT Router

type decoySession struct {
	donorConn  *net.UDPConn
	lastActive time.Time
}

type DecoyNAT struct {
	closed       bool
	done         chan struct{}
	mu           sync.RWMutex
	sessions     map[string]*decoySession
	donorAddr    *net.UDPAddr
	serverSocket net.PacketConn
}

const (
	maxDecoySessions = 512
	decoyIdleTimeout = 10 * time.Second
)

func NewDecoyNAT(serverSocket net.PacketConn, donorHostPort string) (*DecoyNAT, error) {
	return newDecoyNAT(context.Background(), serverSocket, donorHostPort)
}

func newDecoyNAT(ctx context.Context, serverSocket net.PacketConn, donorHostPort string) (*DecoyNAT, error) {
	if donorHostPort == "" {
		return nil, nil
	}
	host, portText, err := net.SplitHostPort(donorHostPort)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || host == "" {
		return nil, errors.New("invalid QUIC donor endpoint")
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve QUIC donor: %w", err)
	}
	if err := resolveCtx.Err(); err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("QUIC donor has no address")
	}
	chosen := addresses[0]
	for _, address := range addresses {
		if address.IP.To4() != nil {
			chosen = address
			break
		}
	}
	donorAddr := &net.UDPAddr{IP: chosen.IP, Zone: chosen.Zone, Port: port}

	nat := &DecoyNAT{
		done:         make(chan struct{}),
		sessions:     make(map[string]*decoySession),
		donorAddr:    donorAddr,
		serverSocket: serverSocket,
	}

	// Session garbage collection
	go nat.gcLoop()
	return nat, nil
}

func (n *DecoyNAT) ForwardToDonor(packet []byte, clientAddr net.Addr) {
	clientKey := clientAddr.String()

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	sess, exists := n.sessions[clientKey]
	if !exists {
		// LRU eviction when pool is full to prevent DoS against legitimate scanners
		if len(n.sessions) >= maxDecoySessions {
			var oldestKey string
			var oldestTime time.Time
			first := true
			for k, s := range n.sessions {
				if first || s.lastActive.Before(oldestTime) {
					oldestTime = s.lastActive
					oldestKey = k
					first = false
				}
			}
			if oldestKey != "" {
				n.sessions[oldestKey].donorConn.Close()
				delete(n.sessions, oldestKey)
			}
		}

		// Outbound UDP socket to genuine HTTP/3 donor
		donorConn, err := net.DialUDP("udp", nil, n.donorAddr)
		if err != nil {
			n.mu.Unlock()
			log.Printf("[DECOY-NAT] Failed to dial donor %s: %v", n.donorAddr, err)
			return
		}

		sess = &decoySession{
			donorConn:  donorConn,
			lastActive: time.Now(),
		}
		n.sessions[clientKey] = sess
		n.mu.Unlock()

		// Reverse proxy loop: Donor -> Server -> Client
		go n.reverseProxyLoop(sess, clientKey, clientAddr)
	} else {
		sess.lastActive = time.Now()
		n.mu.Unlock()
	}

	// Relay datagram to donor
	if _, err := sess.donorConn.Write(packet); err != nil {
		log.Printf("[DECOY-NAT] Forward to donor error: %v", err)
	}
}

func (n *DecoyNAT) reverseProxyLoop(sess *decoySession, clientKey string, clientAddr net.Addr) {
	defer func() {
		sess.donorConn.Close()
		n.mu.Lock()
		if n.sessions[clientKey] == sess {
			delete(n.sessions, clientKey)
		}
		n.mu.Unlock()
	}()

	bufPtr := demuxPacketPool.Get().(*[]byte)
	defer demuxPacketPool.Put(bufPtr)
	buf := *bufPtr

	for {
		_ = sess.donorConn.SetReadDeadline(time.Now().Add(decoyIdleTimeout))
		bytesRead, err := sess.donorConn.Read(buf)
		if err != nil {
			break
		}

		n.mu.Lock()
		sess.lastActive = time.Now()
		n.mu.Unlock()

		// Relay donor response back to client
		if _, err := n.serverSocket.WriteTo(buf[:bytesRead], clientAddr); err != nil {
			break
		}
	}
}

func (n *DecoyNAT) gcLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
		}
		n.mu.Lock()
		now := time.Now()
		for key, sess := range n.sessions {
			if now.Sub(sess.lastActive) > decoyIdleTimeout {
				sess.donorConn.Close()
				delete(n.sessions, key)
			}
		}
		n.mu.Unlock()
	}
}

func (n *DecoyNAT) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return
	}
	n.closed = true
	close(n.done)
	for key, sess := range n.sessions {
		_ = sess.donorConn.Close()
		delete(n.sessions, key)
	}
}

// DemuxPacketConn multiplexer for quic-go

var demuxPacketPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

type authPacket struct {
	bufPtr *[]byte
	length int
	addr   net.Addr
}

const shardCount = 32

type ShardedAuthMap struct {
	shards [shardCount]*authShard
}

type authShard struct {
	sync.RWMutex
	clients map[string]time.Time
}

func NewShardedAuthMap() *ShardedAuthMap {
	m := &ShardedAuthMap{}
	for i := 0; i < shardCount; i++ {
		m.shards[i] = &authShard{clients: make(map[string]time.Time)}
	}
	return m
}

func (m *ShardedAuthMap) getShard(key string) *authShard {
	// FNV-1a hash
	var hash uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return m.shards[hash%shardCount]
}

func (m *ShardedAuthMap) Get(key string) (time.Time, bool) {
	shard := m.getShard(key)
	shard.RLock()
	val, ok := shard.clients[key]
	shard.RUnlock()
	return val, ok
}

func (m *ShardedAuthMap) Set(key string, val time.Time) {
	shard := m.getShard(key)
	shard.Lock()
	shard.clients[key] = val
	shard.Unlock()
}

// RefreshExisting never inserts unknown keys or revives expired authorizations.
func (m *ShardedAuthMap) RefreshExisting(key string, now time.Time, maxAge time.Duration) bool {
	shard := m.getShard(key)
	// Coalesce refreshes: this can only make idle expiry stricter, never later.
	shard.RLock()
	last, ok := shard.clients[key]
	if !ok || now.Sub(last) >= maxAge {
		shard.RUnlock()
		return false
	}
	refreshInterval := maxAge / 4
	if refreshInterval > time.Second {
		refreshInterval = time.Second
	}
	if now.Sub(last) < refreshInterval {
		shard.RUnlock()
		return true
	}
	shard.RUnlock()
	shard.Lock()
	defer shard.Unlock()
	last, ok = shard.clients[key]
	if !ok || now.Sub(last) >= maxAge {
		return false
	}
	shard.clients[key] = now
	return true
}

func (m *ShardedAuthMap) Delete(key string) {
	shard := m.getShard(key)
	shard.Lock()
	delete(shard.clients, key)
	shard.Unlock()
}

func (m *ShardedAuthMap) Cleanup(cutoff time.Time) {
	for i := 0; i < shardCount; i++ {
		shard := m.shards[i]
		shard.Lock()
		for k, t := range shard.clients {
			if t.Before(cutoff) {
				delete(shard.clients, k)
			}
		}
		shard.Unlock()
	}
}

type DemuxPacketConn struct {
	deadlineMu      sync.Mutex
	readDeadline    time.Time
	deadlineChanged chan struct{}
	rawConn         net.PacketConn
	authQueue       chan authPacket
	decoyNAT        *DecoyNAT
	secretKey       []byte
	closed          chan struct{}
	once            sync.Once

	// Sharded session tables (Lock Sharding)
	authClients *ShardedAuthMap // key: client IP:Port -> lastSeen
	authCIDs    *ShardedAuthMap // key: 16-byte hex/string DCID -> lastSeen
	admission   *admissionGate
	direct      *directQUICGate
	wireVersion int
	legacyWire  bool
}

func NewDemuxPacketConn(rawConn net.PacketConn, secretKey []byte, donorHostPort string) (*DemuxPacketConn, error) {
	version, legacy := 0, false
	if cfg != nil {
		version, legacy = cfg.WireVersion, cfg.LegacyWire
	}
	return newDemuxPacketConn(rawConn, secretKey, donorHostPort, version, legacy, activeAdmission.Load(), serverStaticECDH)
}

// Listener policy is captured before its goroutines start. Changing the default
// configuration must not change admission rules of an already running socket.
func newDemuxPacketConn(rawConn net.PacketConn, secretKey []byte, donorHostPort string, version int, legacy bool, admission *admissionGate, identity *ecdh.PrivateKey) (*DemuxPacketConn, error) {
	return newDemuxPacketConnContext(context.Background(), rawConn, secretKey, donorHostPort, version, legacy, admission, identity)
}

func newDemuxPacketConnContext(ctx context.Context, rawConn net.PacketConn, secretKey []byte, donorHostPort string, version int, legacy bool, admission *admissionGate, identity *ecdh.PrivateKey, inboundID ...string) (*DemuxPacketConn, error) {
	decoy, err := newDecoyNAT(ctx, rawConn, donorHostPort)
	if err != nil {
		return nil, err
	}

	d := &DemuxPacketConn{
		deadlineChanged: make(chan struct{}),
		rawConn:         rawConn,
		authQueue:       make(chan authPacket, 16384),
		decoyNAT:        decoy,
		secretKey:       secretKey,
		closed:          make(chan struct{}),
		authClients:     NewShardedAuthMap(),
		authCIDs:        NewShardedAuthMap(),
		admission:       admission,
		wireVersion:     version,
		legacyWire:      legacy,
	}

	if version == 7 {
		d.admission = nil
		d.direct = newDirectQUICGateWithIdentity(identity)
		if len(inboundID) > 0 {
			d.direct.inboundID = inboundID[0]
		}
	}
	go d.readLoop()
	go d.clientGCLoop()
	return d, nil
}

// extractDCID extracts Destination Connection ID from QUIC packet (RFC 9000):
// - Long Header: offset 6, length dcil
// - 1-RTT Short Header: offset 1, 16 bytes
func extractDCID(p []byte) string {
	if len(p) < 5 {
		return ""
	}
	first := p[0]
	if (first & 0x80) != 0 {
		// Long Header
		if len(p) < 6 {
			return ""
		}
		dcil := int(p[5])
		if dcil > 0 && dcil <= 20 && len(p) >= 6+dcil {
			return string(p[6 : 6+dcil])
		}
	} else {
		// 1-RTT Short Header (RFC 9000 17.3)
		const defaultCIDLen = 16
		if first&0x40 != 0 && len(p) >= 1+defaultCIDLen {
			return string(p[1 : 1+defaultCIDLen])
		}
	}
	return ""
}

func (d *DemuxPacketConn) readLoop() {
	reader := newDemuxPacketReader(d.rawConn)
	for {
		rawPkt, addr, err := reader.ReadPacket()
		if err != nil {
			select {
			case <-d.closed:
				return
			default:
				_ = d.Close()
				return
			}
		}

		if d.direct != nil && needsFreshQUICAdmission(rawPkt) {
			packets, accepted, held := d.direct.accept(rawPkt, addr)
			if held {
				continue
			}
			for _, packet := range packets {
				if accepted {
					d.authCIDs.Set(extractDCID(packet), time.Now())
					d.dispatchToQUIC(packet, addr)
				} else if d.decoyNAT != nil {
					d.decoyNAT.ForwardToDonor(packet, addr)
				}
			}
			continue
		}
		// Address-independent CID admission preserves NAT rebinding without
		// address formatting/map writes on every packet. quic-go validates AEAD
		// and migration, while quicpeer binds users to the actual TLS exporter.
		// A known address alone never admits a malformed/CID-less packet.
		dcidKey := extractDCID(rawPkt)
		freshAdmission := d.admission != nil && !d.legacyWire && needsFreshQUICAdmission(rawPkt)
		if !freshAdmission && dcidKey != "" && d.authCIDs.RefreshExisting(dcidKey, time.Now(), 300*time.Second) {
			d.dispatchToQUIC(rawPkt, addr)
			continue
		}

		// Check QUIC Initial
		if d.admission != nil && d.admission.admit(rawPkt, addr) {
			d.authCIDs.Set(extractDCID(rawPkt), time.Now())
			d.dispatchToQUIC(rawPkt, addr)
			continue
		}
		if ok, authUser := d.validateLegacyInitial(rawPkt); ok {
			addrStr := addr.String()
			log.Printf("[QUIC-DEMUX] Authorized plain QUIC Initial from %s (user: %s)", addrStr, authUser)
			setLastAuthorizedUser(authUser)
			bindAuthenticatedUser(addrStr, authUser)
			d.recordAuth(addrStr, rawPkt)
			d.dispatchToQUIC(rawPkt, addr)
			continue
		}

		// Fallback unauthenticated packet to Decoy-NAT if donor is available and packet resembles QUIC/TLS
		// RFC 9000: Short Header has bit 7 == 0 and bit 6 (Fixed Bit) == 1 (len >= 20).
		isQUICorTLS := (len(rawPkt) >= 5 && ((rawPkt[0]&0x80) != 0 || rawPkt[0] == 0x16)) ||
			(len(rawPkt) >= 20 && (rawPkt[0]&0x80) == 0 && (rawPkt[0]&0x40) != 0)
		if isQUICorTLS && d.decoyNAT != nil {
			// Avoid one attacker-controlled log entry per unauthenticated packet.
			d.decoyNAT.ForwardToDonor(rawPkt, addr)
		} else {
			// Without a donor, unknown packets are dropped without a VPN response.
		}
	}
}

// An observed CID is a routing hint, not permission to start a new TLS session.
// Handshake/1-RTT packets still use the CID fast path for loss and migration.
func needsFreshQUICAdmission(packet []byte) bool {
	if len(packet) < 5 || packet[0]&0x80 == 0 {
		return false
	}
	typ := (packet[0] >> 4) & 3
	switch binary.BigEndian.Uint32(packet[1:5]) {
	case 1:
		return typ == 0
	case 0x6b3343cf:
		return typ == 1
	default:
		// Unknown versions belong on the donor path, not the private listener's
		// version-negotiation path, even if a captured DCID is still cached.
		return true
	}
}

func (d *DemuxPacketConn) recordAuth(addrStr string, quicInitialPkt []byte) {
	now := time.Now()
	d.authClients.Set(addrStr, now)
	authUser := getBoundAuthenticatedUser(addrStr)

	dcidKey := extractDCID(quicInitialPkt)
	if dcidKey != "" {
		d.authCIDs.Set(dcidKey, now)
		if authUser != "" {
			bindAuthenticatedUser(dcidKey, authUser)
		}
	}
	if len(quicInitialPkt) > 6 {
		dcil := int(quicInitialPkt[5])
		scilOffset := 6 + dcil
		if len(quicInitialPkt) > scilOffset {
			scil := int(quicInitialPkt[scilOffset])
			if scil > 0 && len(quicInitialPkt) >= scilOffset+1+scil {
				scidKey := string(quicInitialPkt[scilOffset+1 : scilOffset+1+scil])
				d.authCIDs.Set(scidKey, now)
				if authUser != "" {
					bindAuthenticatedUser(scidKey, authUser)
				}
			}
		}
	}
}

func (d *DemuxPacketConn) dispatchToQUIC(data []byte, addr net.Addr) {
	bufPtr := demuxPacketPool.Get().(*[]byte)
	if len(*bufPtr) < len(data) {
		*bufPtr = make([]byte, len(data))
	}
	copy(*bufPtr, data)

	select {
	case d.authQueue <- authPacket{bufPtr: bufPtr, length: len(data), addr: addr}:
	default:
		// Queue full under peak traffic: drop immediately without stalling the read thread
		demuxPacketPool.Put(bufPtr)
	}
}

func (d *DemuxPacketConn) clientGCLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.closed:
			return
		case <-ticker.C:
		}
		cutoff := time.Now().Add(-300 * time.Second)
		d.authClients.Cleanup(cutoff)
		d.authCIDs.Cleanup(cutoff)
		if d.admission != nil {
			d.admission.prune()
		}
	}
}

func (d *DemuxPacketConn) validateLegacyInitial(packet []byte) (bool, string) {
	if d.direct != nil {
		return false, ""
	}
	if d.admission != nil && !d.legacyWire {
		return false, ""
	}
	return validateQUICInitial(packet, d.secretKey)
}

// ReadFrom implements net.PacketConn for quic-go.
func (d *DemuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		d.deadlineMu.Lock()
		deadline, changed := d.readDeadline, d.deadlineChanged
		d.deadlineMu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expired = timer.C
		}
		stopTimer := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case <-d.closed:
			stopTimer()
			return 0, nil, net.ErrClosed
		case <-changed:
			stopTimer()
			continue
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case pkt := <-d.authQueue:
			stopTimer()
			n := copy(p, (*pkt.bufPtr)[:pkt.length])
			if n < pkt.length {
				log.Printf("[QUIC-DEMUX] Buffer overflow: packet %d bytes, quic-go buffer %d bytes", pkt.length, len(p))
			}
			demuxPacketPool.Put(pkt.bufPtr)
			return n, retryAddressVersion(pkt.addr, d.wireVersion), nil
		}
	}
}

func (d *DemuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	addr = rawPeerAddress(addr)
	d.recordOutgoingQUIC(p, addr)
	return d.rawConn.WriteTo(p, addr)
}

func (d *DemuxPacketConn) recordOutgoingQUIC(p []byte, addr net.Addr) {
	// Intercept server's Source Connection ID in Handshake packets
	if len(p) > 6 && (p[0]&0x80) != 0 {
		now := time.Now()
		authUser := getBoundAuthenticatedUser(addr.String())
		dcil := int(p[5])
		scilOffset := 6 + dcil
		if len(p) > scilOffset {
			scil := int(p[scilOffset])
			if scil > 0 && len(p) >= scilOffset+1+scil {
				serverSCID := string(p[scilOffset+1 : scilOffset+1+scil])
				d.authCIDs.Set(serverSCID, now)
				if authUser != "" {
					bindAuthenticatedUser(serverSCID, authUser)
				}
			}
		}
	}
	// Outgoing DCIDs belong to clients, not to our receive table; short-header
	// lengths can differ. Register only our source CIDs, never client DCIDs.
}

func (d *DemuxPacketConn) Close() error {
	d.once.Do(func() {
		close(d.closed)
		if d.decoyNAT != nil {
			d.decoyNAT.Close()
		}
		d.rawConn.Close()
	})
	return nil
}

func (d *DemuxPacketConn) LocalAddr() net.Addr { return d.rawConn.LocalAddr() }
func (d *DemuxPacketConn) SetDeadline(t time.Time) error {
	if err := d.SetReadDeadline(t); err != nil {
		return err
	}
	return d.rawConn.SetWriteDeadline(t)
}
func (d *DemuxPacketConn) SetReadDeadline(t time.Time) error {
	d.deadlineMu.Lock()
	defer d.deadlineMu.Unlock()
	d.readDeadline = t
	close(d.deadlineChanged)
	d.deadlineChanged = make(chan struct{})
	return nil
}
func (d *DemuxPacketConn) SetWriteDeadline(t time.Time) error { return d.rawConn.SetWriteDeadline(t) }
