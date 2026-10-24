package main

import (
	"atlant.local/protocol/realityauth"
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type userRecord struct {
	UpBytes    uint64 `json:"up_bytes"`           // Total uploaded bytes
	DownBytes  uint64 `json:"down_bytes"`         // Total downloaded bytes
	TotalLimit uint64 `json:"total_limit"`        // Max total bytes (up + down), 0 = unlimited
	ExpiresAt  int64  `json:"expires_at"`         // Unix expiration timestamp (sec), 0 = never
	CreatedAt  int64  `json:"created_at"`         // Unix creation timestamp (sec)
	LastSeen   int64  `json:"last_seen"`          // Unix timestamp of last activity (sec)
	Name       string `json:"name"`               // User name
	PBK        string `json:"pbk"`                // User secret key (hex)
	Enabled    bool   `json:"enabled"`            // Enabled status (default true)
	LastIP     string `json:"last_ip,omitempty"`  // Last seen client IP address
	Note       string `json:"note,omitempty"`     // Optional note or description
	IPLimit    int    `json:"ip_limit,omitempty"` // Max concurrent IPs (0 = unlimited)
}

type userDB struct {
	Version       int                    `json:"version"`
	Users         map[string]*userRecord `json:"users"`
	Subscriptions []SubscriptionRecord   `json:"subscriptions"`
}

// Legacy files may omit enabled. Preserve the documented enabled-by-default
// behavior without turning an explicitly disabled account back on after load.
func (rec *userRecord) UnmarshalJSON(data []byte) error {
	type plainUser userRecord
	parsed := plainUser{Enabled: true}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	*rec = userRecord(parsed)
	return nil
}

type UserStorage interface {
	GetUserPBK(name string) (string, bool)
	GetUserByTag(tag [4]byte) (*userRecord, bool)
	AddUser(name, pbk string) error
	DeleteUser(name string) error
}

type MemoryCachedStorage struct {
	byName sync.Map // key: username (string) -> pbk (string)
	byTag  sync.Map // key: [4]byte -> *userRecord
}

type OnlineSession struct {
	ID          uint64    `json:"id"`
	User        string    `json:"user"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	DurationSec int64     `json:"duration_sec"`
}

type activeSessionItem struct {
	id          uint64
	user        string
	remoteAddr  string
	connectedAt time.Time
	closer      func()
}

var (
	usersMu           sync.RWMutex
	usersDB           = &userDB{Version: 1, Users: map[string]*userRecord{}}
	usersStorage      = &MemoryCachedStorage{}
	lastUsersMTime    time.Time
	userActiveConns   sync.Map // key: username -> *atomic.Int32
	usersDirty        atomic.Bool
	sessionSeq        atomic.Uint64
	activeSessions    sync.Map // map[uint64]*activeSessionItem
	realtimeTotalUp   uint64
	realtimeTotalDown uint64
	lastSpeedCalc     = time.Now()
	lastSpeedUp       uint64
	lastSpeedDown     uint64
	currentUpBps      uint64
	currentDownBps    uint64
	speedMu           sync.Mutex
)

func trackUserSession(name string, remoteAddr string, closer func()) func() {
	if name == "" {
		return func() {}
	}
	inc := incUserActiveConns(name)
	id := sessionSeq.Add(1)
	item := &activeSessionItem{
		id:          id,
		user:        name,
		remoteAddr:  remoteAddr,
		connectedAt: time.Now(),
		closer:      closer,
	}
	activeSessions.Store(id, item)

	// Record last client IP
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && host != "" {
		usersMu.Lock()
		if rec, ok := usersDB.Users[name]; ok && rec != nil {
			rec.LastIP = host
		}
		usersMu.Unlock()
	}

	return func() {
		activeSessions.Delete(id)
		inc()
	}
}

var sessionAdmissionMu sync.Mutex

// Reserve the observed IP and session atomically; another session from the
// same IP does not consume an additional IP slot.
func reserveUserSession(name, remoteAddr string, closer func()) (func(), error) {
	sessionAdmissionMu.Lock()
	defer sessionAdmissionMu.Unlock()
	if !isUserAllowed(name) || getUserActiveConns(name) >= 1024 {
		return nil, fmt.Errorf("session admission rejected")
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("invalid session peer")
	}
	usersMu.RLock()
	record := usersDB.Users[name]
	if record == nil {
		usersMu.RUnlock()
		return nil, fmt.Errorf("user removed during admission")
	}
	limit := record.IPLimit
	usersMu.RUnlock()
	limit = subscriptionIPLimit(name, limit)
	if limit > 0 {
		ips := make(map[string]bool)
		activeSessions.Range(func(_, value any) bool {
			item := value.(*activeSessionItem)
			if item.user == name {
				ip, _, _ := net.SplitHostPort(item.remoteAddr)
				ips[ip] = true
			}
			return true
		})
		if !ips[host] && len(ips) >= limit {
			return nil, fmt.Errorf("IP limit reached")
		}
	}
	cleanup := trackUserSession(name, remoteAddr, closer)
	var once sync.Once
	return func() {
		once.Do(func() {
			sessionAdmissionMu.Lock()
			defer sessionAdmissionMu.Unlock()
			cleanup()
		})
	}, nil
}

func getOnlineSessions() []OnlineSession {
	var list []OnlineSession
	now := time.Now()
	activeSessions.Range(func(key, value any) bool {
		if item, ok := value.(*activeSessionItem); ok && item != nil {
			list = append(list, OnlineSession{
				ID:          item.id,
				User:        item.user,
				RemoteAddr:  item.remoteAddr,
				ConnectedAt: item.connectedAt,
				DurationSec: int64(now.Sub(item.connectedAt).Seconds()),
			})
		}
		return true
	})
	return list
}

func kickUserSessions(name string) int {
	if gate := activeAdmission.Load(); gate != nil {
		if name == "all" || name == "*" {
			gate.store.RevokeAll()
		} else {
			gate.store.RevokeSubject(name)
		}
	}
	var toClose []func()
	activeSessions.Range(func(key, value any) bool {
		if item, ok := value.(*activeSessionItem); ok && item != nil {
			if name == "all" || name == "*" || item.user == name {
				if item.closer != nil {
					toClose = append(toClose, item.closer)
				}
			}
		}
		return true
	})
	for _, c := range toClose {
		c()
	}
	return len(toClose)
}

func getRealtimeSpeed() (uint64, uint64) {
	speedMu.Lock()
	defer speedMu.Unlock()
	now := time.Now()
	elapsed := now.Sub(lastSpeedCalc).Seconds()
	if elapsed >= 1.0 {
		up := atomic.LoadUint64(&realtimeTotalUp)
		down := atomic.LoadUint64(&realtimeTotalDown)
		if up >= lastSpeedUp {
			currentUpBps = uint64(float64(up-lastSpeedUp) / elapsed)
		}
		if down >= lastSpeedDown {
			currentDownBps = uint64(float64(down-lastSpeedDown) / elapsed)
		}
		lastSpeedUp = up
		lastSpeedDown = down
		lastSpeedCalc = now
	}
	return currentUpBps, currentDownBps
}

func incUserActiveConns(name string) func() {
	if name == "" {
		return func() {}
	}
	val, _ := userActiveConns.LoadOrStore(name, &atomic.Int32{})
	ctr := val.(*atomic.Int32)
	ctr.Add(1)
	return func() {
		ctr.Add(-1)
	}
}

func getUserActiveConns(name string) int32 {
	if val, ok := userActiveConns.Load(name); ok {
		c := val.(*atomic.Int32).Load()
		if c < 0 {
			return 0
		}
		return c
	}
	return 0
}

func recordUserTraffic(name string, upBytes, downBytes uint64) bool {
	if name == "" || (upBytes == 0 && downBytes == 0) {
		return name != ""
	}
	usersMu.Lock()
	rec, ok := usersDB.Users[name]
	budget := quotaBudgetLocked(name)
	allowed := ok && rec != nil && rec.Enabled && subscriptionUserAllowed(name) && (rec.ExpiresAt == 0 || time.Now().Unix() < rec.ExpiresAt) && (budget != nil || !subscriptionRequiresQuota(name))
	if allowed && budget == nil && rec.TotalLimit > 0 {
		used := totalTraffic(atomic.LoadUint64(&rec.UpBytes), atomic.LoadUint64(&rec.DownBytes))
		amount := totalTraffic(upBytes, downBytes)
		allowed = used < rec.TotalLimit && amount <= rec.TotalLimit-used
	}
	if allowed && budget != nil {
		usersMu.Unlock()
		allowed = budget.consume(upBytes, downBytes)
		usersMu.Lock()
		rec = usersDB.Users[name]
		allowed = allowed && rec != nil && rec.Enabled && subscriptionUserAllowed(name) && (rec.ExpiresAt == 0 || time.Now().Unix() < rec.ExpiresAt) && quotaBudgetLocked(name) == budget
	}
	if allowed {
		addTrafficCounter(&rec.UpBytes, upBytes)
		addTrafficCounter(&rec.DownBytes, downBytes)
		atomic.StoreInt64(&rec.LastSeen, time.Now().Unix())
		usersDirty.Store(true)
	}
	usersMu.Unlock()
	if !allowed {
		kickUserSessions(name)
		return false
	}
	addTrafficCounter(&realtimeTotalUp, upBytes)
	addTrafficCounter(&realtimeTotalDown, downBytes)
	return true
}

func getUserActiveIPCount(name string) int {
	if name == "" {
		return 0
	}
	uniqueIPs := make(map[string]struct{})
	activeSessions.Range(func(key, value any) bool {
		if item, ok := value.(*activeSessionItem); ok && item != nil && item.user == name {
			if host, _, err := net.SplitHostPort(item.remoteAddr); err == nil && host != "" {
				uniqueIPs[host] = struct{}{}
			} else if item.remoteAddr != "" {
				uniqueIPs[item.remoteAddr] = struct{}{}
			}
		}
		return true
	})
	return len(uniqueIPs)
}

func isUserAllowed(name string) bool {
	if name == "" || !subscriptionUserAllowed(name) {
		return false
	}
	usersMu.RLock()
	defer usersMu.RUnlock()
	rec, ok := usersDB.Users[name]
	if !ok || rec == nil {
		return false
	}
	if !rec.Enabled {
		return false
	}
	now := time.Now().Unix()
	if rec.ExpiresAt > 0 && now >= rec.ExpiresAt {
		return false
	}
	if budget := quotaBudgetLocked(name); budget != nil {
		return budget.valid()
	}
	if subscriptionRequiresQuota(name) {
		return false
	}
	if trafficLimitReached(atomic.LoadUint64(&rec.UpBytes), atomic.LoadUint64(&rec.DownBytes), rec.TotalLimit) {
		return false
	}
	return true
}

func enforceActiveUserLimits() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		users := make(map[string]bool)
		activeSessions.Range(func(_, value any) bool { users[value.(*activeSessionItem).user] = true; return true })
		for name := range users {
			if !isUserAllowed(name) {
				kickUserSessions(name)
			}
		}
	}
}

func startStatsFlusher(path string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if usersDirty.Load() {
			if err := saveUsers(path); err != nil {
				usersDirty.Store(true)
			}
		}
	}
}

func generateAtlantLink(username, pbk string) string {
	if cfg == nil {
		return ""
	}
	host := cfg.ServerAddr
	runtime := cfg.Runtime()
	if strings.TrimSpace(runtime.AdvertiseAddr) != "" {
		host = strings.TrimSpace(runtime.AdvertiseAddr)
	}

	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h = host
		p = "443"
	}

	if h == "0.0.0.0" || h == "" || h == "::" {
		h = getOutboundIP()
	}

	if net.ParseIP(h) == nil {
		if ips, err := net.LookupIP(h); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					h = ip4.String()
					break
				}
			}
		}
	}
	host = net.JoinHostPort(h, p)

	spk := getServerStaticPubHex()
	link := fmt.Sprintf("atlant://%s?sni=%s&user=%s&pbk=%s",
		host,
		url.QueryEscape(runtime.SNI),
		url.QueryEscape(username),
		url.QueryEscape(pbk),
	)
	if spk != "" {
		link += "&server_pub_key=" + url.QueryEscape(spk)
	}
	version := cfg.WireVersion
	if version == 0 {
		version = 2
	}
	link += fmt.Sprintf("&wire_version=%d", version)
	return link
}

func reloadUsersIfModified(path string) bool {
	// SQLite is the authority. Legacy JSON is import-only and never reloaded
	// from an authentication request. Exactly one process owns the writer.
	return false
}

func watchUsersFile(path string) {
	for {
		time.Sleep(3 * time.Second)
		reloadUsersIfModified(path)
	}
}

func (s *MemoryCachedStorage) GetUserPBK(name string) (string, bool) {
	val, ok := s.byName.Load(name)
	if !ok {
		return "", false
	}
	return val.(string), true
}

type userList struct {
	records []*userRecord
}

func (s *MemoryCachedStorage) GetUsersByTag(tag [4]byte) []*userRecord {
	val, ok := s.byTag.Load(tag)
	if !ok || val == nil {
		return nil
	}
	return val.(*userList).records
}

func (s *MemoryCachedStorage) GetUserByTag(tag [4]byte) (*userRecord, bool) {
	users := s.GetUsersByTag(tag)
	if len(users) == 0 {
		return nil, false
	}
	return users[0], true
}

func (s *MemoryCachedStorage) AddUser(name, pbk string) error {
	invalidateUserPBKCache(name)
	rec := &userRecord{Name: name, PBK: pbk}
	tag := getUserTag(name)
	s.byName.Store(name, pbk)

	// Collision-safe tag mapping (appends or updates existing slice)
	for {
		val, loaded := s.byTag.Load(tag)
		if !loaded || val == nil {
			if _, loaded := s.byTag.LoadOrStore(tag, &userList{records: []*userRecord{rec}}); !loaded {
				break
			}
			continue
		}

		oldWrapper := val.(*userList)
		list := make([]*userRecord, len(oldWrapper.records))
		copy(list, oldWrapper.records)

		found := false
		for i, existing := range list {
			if existing.Name == name {
				list[i] = rec
				found = true
				break
			}
		}
		if !found {
			list = append(list, rec)
		}
		newWrapper := &userList{records: list}
		if s.byTag.CompareAndSwap(tag, val, newWrapper) {
			break
		}
	}
	return nil
}

func (s *MemoryCachedStorage) DeleteUser(name string) error {
	invalidateUserPBKCache(name)
	tag := getUserTag(name)
	s.byName.Delete(name)

	for {
		val, ok := s.byTag.Load(tag)
		if !ok || val == nil {
			break
		}
		oldWrapper := val.(*userList)
		var updated []*userRecord
		for _, u := range oldWrapper.records {
			if u.Name != name {
				updated = append(updated, u)
			}
		}
		if len(updated) == 0 {
			if s.byTag.CompareAndDelete(tag, val) {
				break
			}
		} else {
			newWrapper := &userList{records: updated}
			if s.byTag.CompareAndSwap(tag, val, newWrapper) {
				break
			}
		}
	}
	return nil
}

func syncStorageFromDBLocked() {
	// Reload/restore replaces the whole database, so remove stale credentials too.
	usersStorage.byName.Range(func(key, value any) bool {
		name := key.(string)
		if rec, ok := usersDB.Users[name]; !ok || rec == nil {
			_ = usersStorage.DeleteUser(name)
		}
		return true
	})
	// Sync in-memory sync.Map cache
	for name, rec := range usersDB.Users {
		_ = usersStorage.AddUser(name, rec.PBK)
	}
}

func validateUserDB(db *userDB) error {
	if db.Users == nil {
		return fmt.Errorf("users object is required")
	}
	if db.Version == 0 {
		db.Version = 1
	}
	if db.Version != 1 {
		return fmt.Errorf("unsupported users database version")
	}
	for name, rec := range db.Users {
		if !isValidUsername(name) || rec == nil || strings.TrimSpace(rec.PBK) == "" {
			return fmt.Errorf("invalid user record")
		}
		if rec.Name == "" {
			rec.Name = name
		}
		if rec.Name != name {
			return fmt.Errorf("user name does not match database key")
		}
	}
	return nil
}

func loadUsers(path string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	alreadyOpen := currentUsersStore != nil
	store, err := usersStoreLocked(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if alreadyOpen && usersDirty.Load() {
		if err := store.save(ctx, usersDB, ""); err != nil {
			return err
		}
	}
	db, err := store.load(ctx)
	if err != nil {
		return err
	}
	usersDB = db
	syncStorageFromDBLocked()
	if err := reloadQuotaBindingsLocked(); err != nil {
		return err
	}
	usersDirty.Store(false)
	log.Printf("[USERS] Loaded %d users from SQLite %s", len(usersDB.Users), store.path)
	return nil
}

// Caller holds usersMu for writing, including during initial database creation.
func saveUsersLocked(path string, db *userDB) error {
	store, err := usersStoreLocked(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return store.save(ctx, db, "")
}

func saveUsers(path string) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	err := saveUsersLocked(path, usersDB)
	if err != nil {
		log.Printf("[USERS] Save failed: %v", err)
		usersDirty.Store(true)
	} else {
		usersDirty.Store(false)
	}
	return err
}

func isValidUsername(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func getOrCreateUser(path, name, initialPBK string) (*userRecord, bool) {
	name = strings.TrimSpace(name)
	if !isValidUsername(name) {
		log.Printf("[USERS] Invalid username '%s': only alphanumeric, underscore and hyphen (1-64 chars) allowed", name)
		return nil, false
	}

	if initialPBK != "" && (!isValidHex(initialPBK) || len(initialPBK) != 64) {
		log.Printf("[USERS] New PBK must be 64 hex characters")
		return nil, false
	}
	var rec *userRecord
	err := updateUsers(path, func(db *userDB) error {
		rec = db.Users[name]
		if rec != nil && rec.PBK != "" {
			if initialPBK != "" {
				rec.PBK = initialPBK
			}
			return nil
		}
		key := initialPBK
		if key == "" {
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				return err
			}
			key = hex.EncodeToString(random[:])
		}
		rec = &userRecord{Name: name, PBK: key, Enabled: true, CreatedAt: time.Now().Unix()}
		db.Users[name] = rec
		return nil
	})
	if err != nil {
		log.Printf("[USERS] User change not committed: %v", err)
		return nil, false
	}
	if initialPBK != "" {
		go kickUserSessions(name)
	}
	return rec, true
}

func getUserTag(username string) [4]byte {
	h := sha256.Sum256([]byte(username))
	var tag [4]byte
	copy(tag[:], h[:4])
	return tag
}

func validateUserTag(tag [4]byte) bool {
	_, ok := usersStorage.GetUserByTag(tag)
	return ok
}

// authenticateSessionID validates sessionID with clientPubKey binding.
// Returns (userName, userPBK, nonce, isV3, isReplay, ok).
func authenticateSessionID(sessionID []byte, clientPubKey []byte) (string, string, []byte, bool, bool, bool) {
	a, b, c, d, e, f, _ := authenticateSessionIDWire(sessionID, clientPubKey)
	return a, b, c, d, e, f
}

func authenticateSessionIDWire(sessionID, clientPubKey []byte, hello ...[]byte) (string, string, []byte, bool, bool, bool, int) {
	return authenticateSessionIDWithIdentity(cfg, serverStaticECDH, sessionID, clientPubKey, hello...)
}

func authenticateSessionIDWithIdentity(cfg *Config, identity *ecdh.PrivateKey, sessionID, clientPubKey []byte, hello ...[]byte) (string, string, []byte, bool, bool, bool, int) {
	if cfg != nil && (cfg.WireVersion == 3 || cfg.WireVersion == 4 || (cfg.WireVersion == 6 || cfg.WireVersion == 7)) {
		lookup := func(tag [4]byte) []realityauth.Candidate {
			users := usersStorage.GetUsersByTag(tag)
			if len(users) > 16 {
				return make([]realityauth.Candidate, 17)
			}
			result := make([]realityauth.Candidate, 0, len(users))
			for _, u := range users {
				if u != nil {
					key, err := hex.DecodeString(u.PBK)
					if err == nil {
						result = append(result, realityauth.Candidate{Name: u.Name, Key: key})
					}
				}
			}
			return result
		}
		var candidate realityauth.Candidate
		var err error
		if cfg.WireVersion == 6 || cfg.WireVersion == 7 {
			if len(hello) != 1 {
				return "", "", nil, false, false, false, cfg.WireVersion
			}
			candidate, err = realityauth.VerifyHelloVersion(cfg.WireVersion, sessionID, clientPubKey, hello[0], identity, lookup, time.Now())
		} else {
			candidate, err = realityauth.VerifyVersion(cfg.WireVersion, sessionID, clientPubKey, identity, lookup, time.Now())
		}
		if err == nil {
			if (cfg.WireVersion == 6 || cfg.WireVersion == 7) && authTokenUsed(realityReplayKey(cfg.WireVersion, sessionID, clientPubKey)) {
				return "", "", nil, false, true, false, cfg.WireVersion
			}
			if cfg.WireVersion != 6 && cfg.WireVersion != 7 && !consumeAuthToken("wire3:"+hex.EncodeToString(sessionID)+hex.EncodeToString(clientPubKey)) {
				return "", "", nil, false, true, false, cfg.WireVersion
			}
			return candidate.Name, hex.EncodeToString(candidate.Key), nil, true, false, true, cfg.WireVersion
		}
		if !cfg.LegacyWire || cfg.WireVersion == 4 || (cfg.WireVersion == 6 || cfg.WireVersion == 7) {
			return "", "", nil, false, false, false, cfg.WireVersion
		}
	}
	a, b, c, d, e, f := authenticateLegacySessionID(sessionID, clientPubKey)
	return a, b, c, d, e, f, 2
}

func authenticateLegacySessionID(sessionID []byte, clientPubKey []byte) (string, string, []byte, bool, bool, bool) {
	if len(sessionID) != 32 {
		return "", "", nil, false, false, false
	}
	rawTag := sessionID[:4]
	rawNoncePart := sessionID[4:16]  // 12 bytes
	receivedHMAC := sessionID[16:32] // 16 bytes

	// Attempt 1: Protocol V3 (Anti-Signature: rawNonce[:4] masked with sha256("atlant-nonce-v3" || clientPubKey)[:4])
	if len(clientPubKey) == 32 {
		nonceMask := sha256.Sum256(append([]byte("atlant-nonce-v3"), clientPubKey...))
		v3Nonce := make([]byte, 12)
		copy(v3Nonce, rawNoncePart)
		for i := 0; i < 4; i++ {
			v3Nonce[i] ^= nonceMask[i]
		}
		v3TagMask := sha256.Sum256(append(v3Nonce, clientPubKey...))
		var v3UnmaskedTag [4]byte
		for i := 0; i < 4; i++ {
			v3UnmaskedTag[i] = rawTag[i] ^ v3TagMask[i]
		}

		candidates := usersStorage.GetUsersByTag(v3UnmaskedTag)
		if len(candidates) == 0 && cfg != nil && reloadUsersIfModified(cfg.UsersFile) {
			candidates = usersStorage.GetUsersByTag(v3UnmaskedTag)
		}

		for _, user := range candidates {
			if user == nil {
				continue
			}
			pbkBytes, err := hex.DecodeString(user.PBK)
			if err != nil || len(pbkBytes) == 0 {
				continue
			}
			mac := hmac.New(sha256.New, pbkBytes)
			mac.Write(v3Nonce)
			mac.Write(clientPubKey)
			expectedHMAC := mac.Sum(nil)[:16]
			if hmac.Equal(receivedHMAC, expectedHMAC) {
				// Accept at most three minutes of clock drift. The replay cache
				// retains accepted tokens longer than this timestamp window.
				ts := int64(binary.BigEndian.Uint32(v3Nonce[:4]))
				now := time.Now().Unix()
				diff := ts - now
				if diff < -180 || diff > 180 {
					return "", "", nil, false, true, false
				}

				replayKey := hex.EncodeToString(v3Nonce) + hex.EncodeToString(clientPubKey)
				if !consumeAuthToken(replayKey) {
					return "", "", nil, false, true, false
				}

				return user.Name, user.PBK, v3Nonce, true, false, true
			}
		}
	}

	// Older legacy tokens without key-share binding are not accepted here.
	return "", "", nil, false, false, false
}

type UserAuthCandidate struct {
	Name     string
	PBKBytes []byte
}

func getUserAuthCandidates() []UserAuthCandidate {
	usersMu.RLock()
	defer usersMu.RUnlock()
	candidates := make([]UserAuthCandidate, 0, len(usersDB.Users))
	for _, u := range usersDB.Users {
		if u != nil && u.PBK != "" {
			if b := getCachedUserPBKBytes(u); len(b) > 0 {
				candidates = append(candidates, UserAuthCandidate{Name: u.Name, PBKBytes: b})
			}
		}
	}
	return candidates
}

func lookupUserPBK(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	usersMu.RLock()
	defer usersMu.RUnlock()
	rec, ok := usersDB.Users[name]
	if !ok || rec == nil || rec.PBK == "" {
		return "", false
	}
	return rec.PBK, true
}

func startUserCommandLoop() {
	// Commands on server stdin:
	//   key <name>   -> print atlant:// link (single line) for Paste Config
	//   getlink <name> -> alias of key
	//   add user <name> [optional_pbk] -> add or update user
	//   del user <name> -> delete user
	//   help         -> help
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		handleCommand(line)
	}
	if err := in.Err(); err != nil {
		log.Printf("[CMD] stdin error: %v", err)
	}
}

func handleCommand(line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}

	// Commands output to stdout; log.Printf outputs to stderr.
	switch strings.ToLower(fields[0]) {
	case "help", "?":
		fmt.Println("Commands: users, add user <name> [pbk], del user <name>, getlink <name>")
	case "users", "list":
		usersMu.RLock()
		names := make([]string, 0, len(usersDB.Users))
		for n := range usersDB.Users {
			names = append(names, n)
		}
		sort.Strings(names)
		usersMu.RUnlock()
		if len(names) == 0 {
			fmt.Println("No users yet")
			return
		}
		fmt.Println("Users:", strings.Join(names, ", "))
	case "add":
		if len(fields) < 3 || strings.ToLower(fields[1]) != "user" {
			fmt.Println("Usage: add user <name> [optional_pbk]")
			return
		}
		username := fields[2]
		pbk := ""
		if len(fields) >= 4 {
			pbk = fields[3]
		}
		rec, ok := getOrCreateUser(cfg.UsersFile, username, pbk)
		if !ok || rec == nil {
			fmt.Printf("Failed to add user '%s'\n", username)
			return
		}
		fmt.Printf("User '%s' added/updated. Use getlink explicitly to export credentials.\n", username)
	case "del":
		if len(fields) < 3 || strings.ToLower(fields[1]) != "user" {
			fmt.Println("Usage: del user <name>")
			return
		}
		username := fields[2]
		if err := updateUsers(cfg.UsersFile, func(db *userDB) error { delete(db.Users, username); return nil }); err != nil {
			fmt.Printf("Failed to delete user: %v\n", err)
			return
		}
		go kickUserSessions(username)
		fmt.Printf("User '%s' deleted.\n", username)
	case "getlink", "key":
		if len(fields) < 2 {
			fmt.Println("Usage: getlink <username>")
			return
		}
		username := fields[1]

		usersMu.RLock()
		rec, exists := usersDB.Users[username]
		usersMu.RUnlock()

		if !exists || rec == nil {
			fmt.Printf("User '%s' not found.\n", username)
			return
		}
		link := generateAtlantLink(rec.Name, rec.PBK)
		fmt.Println(link)
	default:
		fmt.Printf("Unknown command '%s'. Type 'help'.\n", fields[0])
	}
}

func validateToken(received string, pbk string) bool {
	// DEPRECATED: Use validateAuthToken instead
	log.Printf("[WARNING] validateToken is deprecated, use validateAuthToken")
	return validateAuthToken(received, pbk)
}

func validateAuthToken(token string, pbk string) bool {
	if token == "" || pbk == "" {
		return false
	}

	if len(token) != 32 && len(token) != 144 {
		return false
	}

	if len(token) == 144 {
		// Asymmetric Ed25519 logic
		nonceHex := token[:16]
		sigHex := token[16:]

		nonce, err1 := hex.DecodeString(nonceHex)
		sig, err2 := hex.DecodeString(sigHex)
		seed, err3 := hex.DecodeString(pbk)

		if err1 == nil && err2 == nil && err3 == nil && len(seed) == 32 {
			privKey := ed25519.NewKeyFromSeed(seed)
			pubKey := privKey.Public().(ed25519.PublicKey)

			if ed25519.Verify(pubKey, nonce, sig) {
				if !consumeAuthToken(token) {
					log.Printf("[AUTH] Token already used (replay attack)")
					return false
				}
				log.Printf("[AUTH] Asymmetric crypto token validated successfully")
				return true
			}
		}
	} else if len(token) == 32 {
		// Symmetric HMAC logic
		nonce := token[:16]
		mac := token[16:]

		h := hmac.New(sha256.New, []byte(pbk))
		h.Write([]byte(nonce))
		expectedMac := hex.EncodeToString(h.Sum(nil))[:16]

		if subtle.ConstantTimeCompare([]byte(expectedMac), []byte(mac)) == 1 {
			if !consumeAuthToken(token) {
				log.Printf("[AUTH] Token already used (replay attack)")
				return false
			}
			log.Printf("[AUTH] Symmetric crypto token validated successfully")
			return true
		}
	}

	log.Printf("[AUTH] Validating token failed")
	return false
}

// Cleanup old tokens to prevent memory leaks
// Cleanup old tokens to prevent memory leaks and GC pressure
func cleanupOldTokens() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		tokenMutex.Lock()
		cutoff := time.Now().Add(-15 * time.Minute)
		for token, usedTime := range usedTokens {
			if usedTime.Before(cutoff) {
				delete(usedTokens, token)
			}
		}
		// Bound map size against memory exhaustion attacks
		if len(usedTokens) > 100000 {
			aggressiveCutoff := time.Now().Add(-3 * time.Minute)
			for token, usedTime := range usedTokens {
				if usedTime.Before(aggressiveCutoff) {
					delete(usedTokens, token)
				}
			}
		}
		tokenMutex.Unlock()
	}
}

func isValidHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
