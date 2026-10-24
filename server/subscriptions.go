package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type SubscriptionConfig struct {
	Enabled   bool                  `json:"enabled"`
	Listen    string                `json:"listen"`
	PublicURL string                `json:"public_url"`
	TLS       SubscriptionTLSConfig `json:"tls"`
}

type SubscriptionNode struct {
	Name         string   `json:"name"`
	Server       string   `json:"server"`
	SNI          string   `json:"sni"`
	ServerPubKey string   `json:"server_pub_key"`
	User         string   `json:"user,omitempty"`
	PBK          string   `json:"pbk,omitempty"`
	Transport    string   `json:"transport"`
	WireVersion  int      `json:"wire_version"`
	XHTTPPath    string   `json:"path,omitempty"`
	ServerID     string   `json:"server_id,omitempty"`
	InboundID    string   `json:"inbound_id,omitempty"`
	Transports   []string `json:"transports,omitempty"`
}

type SubscriptionRecord struct {
	Managed      bool                     `json:"managed,omitempty"`
	IPLimit      int                      `json:"ip_limit,omitempty"`
	Note         string                   `json:"note,omitempty"`
	Revision     string                   `json:"revision,omitempty"`
	ID           string                   `json:"id"`
	User         string                   `json:"user"`
	Title        string                   `json:"title"`
	Enabled      bool                     `json:"enabled"`
	ExpiresAt    int64                    `json:"expires_at"`
	UpdateHours  int                      `json:"update_hours"`
	SupportURL   string                   `json:"support_url,omitempty"`
	Announcement string                   `json:"announcement,omitempty"`
	TokenHash    string                   `json:"token_hash,omitempty"`
	Nodes        []SubscriptionNode       `json:"nodes"`
	InboundRefs  []SubscriptionInboundRef `json:"inbound_refs,omitempty"`
	TotalLimit   *uint64                  `json:"total_limit,omitempty"`
	GlobalQuota  *quotaSnapshot           `json:"global_quota,omitempty"`
}

// A configuration revision excludes changing traffic counters but includes the
// token and endpoint credentials. It needs no schema migration and detects
// edits made through any write path, including account attachment and restore.
func subscriptionRevision(s SubscriptionRecord) string {
	s.Revision, s.GlobalQuota = "", nil
	s.Managed = false
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func createSubscriptionTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,user_name TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,title TEXT NOT NULL,enabled INTEGER NOT NULL,expires_at INTEGER NOT NULL,update_hours INTEGER NOT NULL,support_url TEXT NOT NULL,announcement TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS subscription_nodes(subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,position INTEGER NOT NULL,name TEXT NOT NULL,server TEXT NOT NULL,sni TEXT NOT NULL,server_pub_key TEXT NOT NULL,user_name TEXT NOT NULL,pbk TEXT NOT NULL,transport TEXT NOT NULL,wire_version INTEGER NOT NULL,PRIMARY KEY(subscription_id,position));
CREATE TABLE IF NOT EXISTS subscription_inbound_refs(subscription_id TEXT NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,position INTEGER NOT NULL,server_id TEXT NOT NULL,inbound_id TEXT NOT NULL,PRIMARY KEY(subscription_id,position),UNIQUE(subscription_id,server_id,inbound_id));
CREATE TABLE IF NOT EXISTS subscription_node_paths(subscription_id TEXT NOT NULL,position INTEGER NOT NULL,path TEXT NOT NULL,PRIMARY KEY(subscription_id,position),FOREIGN KEY(subscription_id,position) REFERENCES subscription_nodes(subscription_id,position) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS subscription_native_owners(subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,user_name TEXT NOT NULL UNIQUE REFERENCES users(name) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS subscription_client_policy(subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,ip_limit INTEGER NOT NULL CHECK(ip_limit BETWEEN 0 AND 10000),note TEXT NOT NULL);
	`)
	return err
}

func validateSubscription(s *SubscriptionRecord) error {
	if s.IPLimit < 0 || s.IPLimit > 10000 || len(s.Note) > 4096 {
		return errors.New("invalid subscription client policy")
	}
	if len(s.Nodes)+len(s.InboundRefs) > 256 {
		return errors.New("too many subscription profiles")
	}
	if s.TotalLimit != nil && *s.TotalLimit > uint64(quotaMaxValue) {
		return errors.New("quota too large")
	}
	if len(s.ID) != 32 || !isValidHex(s.ID) || !isValidUsername(s.User) || len(s.Title) < 1 || len(s.Title) > 256 || len(s.Announcement) > 2048 || s.ExpiresAt < 0 || s.UpdateHours < 1 || s.UpdateHours > 168 || len(s.Nodes) > 256 || len(s.TokenHash) != 64 || !isValidHex(s.TokenHash) {
		return errors.New("invalid subscription")
	}
	if s.SupportURL != "" {
		u, err := url.Parse(s.SupportURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return errors.New("support URL must use HTTPS")
		}
	}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.ServerID != "" || n.InboundID != "" || len(n.Transports) > 0 {
			return errors.New("use inbound references instead of copied native profiles")
		}
		if n.XHTTPPath != "" && (len(n.XHTTPPath) > 1024 || !strings.HasPrefix(n.XHTTPPath, "/") || strings.ContainsAny(n.XHTTPPath, "?#\r\n\x00")) {
			return errors.New("invalid subscription XHTTP path")
		}
		host, port, err := net.SplitHostPort(n.Server)
		p, e := strconv.Atoi(port)
		if err != nil || e != nil || host == "" || p < 1 || p > 65535 || len(n.Server) > 512 || strings.ContainsAny(host, " /\r\n\t") || len(n.Name) < 1 || len(n.Name) > 256 || len(n.SNI) < 1 || len(n.SNI) > 253 || strings.ContainsAny(n.SNI, " /\r\n\t") {
			return errors.New("invalid subscription node")
		}
		if n.Transport != "reality" && n.Transport != "tcp" && n.Transport != "xhttp" && n.Transport != "quic" {
			return errors.New("invalid node transport")
		}
		if n.WireVersion != 2 && n.WireVersion != 3 && n.WireVersion != 4 && n.WireVersion != 6 && n.WireVersion != 7 {
			return errors.New("explicit wire_version 2, 3, 4, 6 or 7 required")
		}
		if len(n.ServerPubKey) != 64 || !isValidHex(n.ServerPubKey) {
			return errors.New("pinned server public key required")
		}
		if n.User != "" && !isValidUsername(n.User) {
			return errors.New("invalid node user")
		}
		if n.PBK != "" && (len(n.PBK) != 64 || !isValidHex(n.PBK)) {
			return errors.New("invalid node key")
		}
	}
	return nil
}

func writeSubscription(ctx context.Context, tx *sql.Tx, s SubscriptionRecord) error {
	if err := validateSubscription(&s); err != nil {
		return err
	}
	if err := validateSubscriptionInboundRefs(ctx, tx, s.InboundRefs); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET user_name=excluded.user_name,title=excluded.title,enabled=excluded.enabled,expires_at=excluded.expires_at,update_hours=excluded.update_hours,support_url=excluded.support_url,announcement=excluded.announcement,token_hash=excluded.token_hash`, s.ID, s.User, s.Title, s.Enabled, s.ExpiresAt, s.UpdateHours, s.SupportURL, s.Announcement, s.TokenHash); err != nil {
		return err
	}
	if err := writeNativeSubscriptionOwner(ctx, tx, s); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_nodes WHERE subscription_id=?`, s.ID); err != nil {
		return err
	}
	for i, n := range s.Nodes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_nodes VALUES(?,?,?,?,?,?,?,?,?,?)`, s.ID, i, n.Name, n.Server, n.SNI, n.ServerPubKey, n.User, n.PBK, n.Transport, n.WireVersion); err != nil {
			return err
		}
		if n.XHTTPPath != "" {
			if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_node_paths VALUES(?,?,?)`, s.ID, i, n.XHTTPPath); err != nil {
				return err
			}
		}
	}
	return writeSubscriptionInboundRefs(ctx, tx, s.ID, s.InboundRefs)
}

// Called with usersMu held. Rows are materialized before issuing another SQL
// query: the owner intentionally has only one DB connection.
func readSubscriptions(ctx context.Context, store *sqliteUserStore) ([]SubscriptionRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT s.id,s.user_name,s.title,s.enabled,s.expires_at,s.update_hours,s.support_url,s.announcement,s.token_hash,EXISTS(SELECT 1 FROM subscription_native_owners m WHERE m.subscription_id=s.id),COALESCE(p.ip_limit,0),COALESCE(p.note,'') FROM subscriptions s LEFT JOIN subscription_client_policy p ON p.subscription_id=s.id ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	result := make([]SubscriptionRecord, 0)
	for rows.Next() {
		var s SubscriptionRecord
		if err := rows.Scan(&s.ID, &s.User, &s.Title, &s.Enabled, &s.ExpiresAt, &s.UpdateHours, &s.SupportURL, &s.Announcement, &s.TokenHash, &s.Managed, &s.IPLimit, &s.Note); err != nil {
			rows.Close()
			return nil, err
		}
		s.Nodes = []SubscriptionNode{}
		result = append(result, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range result {
		q, qerr := readQuota(ctx, store.db, result[i].ID)
		if qerr == nil {
			limit := uint64(q.Total)
			result[i].TotalLimit = &limit
			result[i].GlobalQuota = &q
		} else if qerr != sql.ErrNoRows {
			return nil, qerr
		}
		r, err := store.db.QueryContext(ctx, `SELECT n.name,n.server,n.sni,n.server_pub_key,n.user_name,n.pbk,n.transport,n.wire_version,COALESCE(p.path,'') FROM subscription_nodes n LEFT JOIN subscription_node_paths p ON p.subscription_id=n.subscription_id AND p.position=n.position WHERE n.subscription_id=? ORDER BY n.position`, result[i].ID)
		if err != nil {
			return nil, err
		}
		for r.Next() {
			var n SubscriptionNode
			if err := r.Scan(&n.Name, &n.Server, &n.SNI, &n.ServerPubKey, &n.User, &n.PBK, &n.Transport, &n.WireVersion, &n.XHTTPPath); err != nil {
				r.Close()
				return nil, err
			}
			result[i].Nodes = append(result[i].Nodes, n)
		}
		err = r.Err()
		r.Close()
		if err != nil {
			return nil, err
		}
		result[i].InboundRefs, err = readSubscriptionInboundRefs(ctx, store, result[i].ID)
		if err != nil {
			return nil, err
		}
		result[i].Revision = subscriptionRevision(result[i])
	}
	return result, nil
}

func subscriptionNodeLink(n SubscriptionNode, user, pbk string) string {
	if n.User != "" {
		user = n.User
	}
	if n.PBK != "" {
		pbk = n.PBK
	}
	q := url.Values{"sni": {n.SNI}, "user": {user}, "pbk": {pbk}, "server_pub_key": {n.ServerPubKey}, "transport": {n.Transport}, "wire_version": {strconv.Itoa(n.WireVersion)}}
	if n.XHTTPPath != "" {
		q.Set("path", n.XHTTPPath)
	}
	if n.ServerID != "" {
		q.Set("server_id", n.ServerID)
	}
	if n.InboundID != "" {
		q.Set("inbound_id", n.InboundID)
	}
	if len(n.Transports) > 0 {
		q.Set("transports", strings.Join(n.Transports, ","))
	}
	u := url.URL{Scheme: "atlant", Host: n.Server, RawQuery: q.Encode(), Fragment: n.Name}
	return u.String()
}

func publicSubscriptionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		http.NotFound(w, r)
		return
	}
	h := sha256.Sum256(raw)
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "unavailable", 503)
		return
	}
	// O(1) indexed token lookup. No scan of all user keys or subscription nodes.
	var s SubscriptionRecord
	err = store.db.QueryRow(`SELECT id,user_name,title,enabled,expires_at,update_hours,support_url,announcement FROM subscriptions WHERE token_hash=?`, hex.EncodeToString(h[:])).Scan(&s.ID, &s.User, &s.Title, &s.Enabled, &s.ExpiresAt, &s.UpdateHours, &s.SupportURL, &s.Announcement)
	if err != nil {
		usersMu.Unlock()
		http.NotFound(w, r)
		return
	}
	u := usersDB.Users[s.User]
	now := time.Now().Unix()
	global, qerr := readQuota(r.Context(), store.db, s.ID)
	if qerr != nil && qerr != sql.ErrNoRows {
		usersMu.Unlock()
		http.Error(w, "unavailable", 503)
		return
	}
	if u == nil || !u.Enabled || !s.Enabled || (s.ExpiresAt > 0 && s.ExpiresAt <= now) || (u.ExpiresAt > 0 && u.ExpiresAt <= now) || (qerr == sql.ErrNoRows && trafficLimitReached(atomic.LoadUint64(&u.UpBytes), atomic.LoadUint64(&u.DownBytes), u.TotalLimit)) {
		usersMu.Unlock()
		http.NotFound(w, r)
		return
	}
	rows, err := store.db.Query(`SELECT n.name,n.server,n.sni,n.server_pub_key,n.user_name,n.pbk,n.transport,n.wire_version,COALESCE(p.path,'') FROM subscription_nodes n LEFT JOIN subscription_node_paths p ON p.subscription_id=n.subscription_id AND p.position=n.position WHERE n.subscription_id=? ORDER BY n.position`, s.ID)
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "unavailable", 503)
		return
	}
	var links []string
	var nodes []SubscriptionNode
	for rows.Next() {
		var n SubscriptionNode
		if err = rows.Scan(&n.Name, &n.Server, &n.SNI, &n.ServerPubKey, &n.User, &n.PBK, &n.Transport, &n.WireVersion, &n.XHTTPPath); err != nil {
			break
		}
		nodes = append(nodes, n)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err == nil {
		var native []SubscriptionNode
		native, err = resolveSubscriptionInboundNodes(r.Context(), store, s.ID)
		nodes = append(nodes, native...)
	}
	if err == nil {
		for _, n := range nodes {
			// Profiles for this server follow current account credentials. A key
			// rotation must not leave an old embedded key in subscription output.
			if n.User != "" && getServerStaticPubHex() != "" && strings.EqualFold(n.ServerPubKey, getServerStaticPubHex()) {
				account := usersDB.Users[n.User]
				if account == nil || !account.Enabled || (account.ExpiresAt > 0 && account.ExpiresAt <= now) {
					continue
				}
				n.PBK = account.PBK
			}
			links = append(links, subscriptionNodeLink(n, u.Name, u.PBK))
		}
	}
	up, down, total, expire := atomic.LoadUint64(&u.UpBytes), atomic.LoadUint64(&u.DownBytes), u.TotalLimit, u.ExpiresAt
	if qerr == nil {
		up, down, total = uint64(global.Up), uint64(global.Down), uint64(global.Total)
	}
	usersMu.Unlock()
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	if s.ExpiresAt > 0 && (expire == 0 || s.ExpiresAt < expire) {
		expire = s.ExpiresAt
	}
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", up, down, total, expire))
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(s.Title)))
	w.Header().Set("Profile-Update-Interval", strconv.Itoa(s.UpdateHours))
	w.Header().Set("X-Subscription-Usage-Scope", "local-account")
	if qerr == nil {
		w.Header().Set("X-Subscription-Usage-Scope", "global-subscription")
		w.Header().Set("X-Subscription-Reserved-Bytes", strconv.FormatInt(global.Reserved, 10))
	}
	if s.SupportURL != "" {
		w.Header().Set("Support-Url", s.SupportURL)
	}
	if s.Announcement != "" {
		w.Header().Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte(s.Announcement)))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	body := strings.Join(links, "\n")
	if r.URL.Query().Get("b64") == "1" {
		body = base64.StdEncoding.EncodeToString([]byte(body))
	}
	ioWriteString(w, body)
}

func ioWriteString(w http.ResponseWriter, s string) { _, _ = w.Write([]byte(s)) }

// Management endpoint is mounted ONLY on the authenticated management server.
// A newly generated URL is returned once; only its SHA-256 is persisted.
func handleAPISubscriptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	usersMu.Lock()
	previousAccess := subscriptionAccess.Load()
	warmUser := ""
	defer func() {
		usersMu.Unlock()
		for _, name := range changedSubscriptionAccess(previousAccess, subscriptionAccess.Load()) {
			kickUserSessions(name)
		}
		if warmUser != "" {
			primeQuotaUser(warmUser)
		}
	}()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 500)
		return
	}
	if r.Method == http.MethodGet {
		list, err := readSubscriptions(r.Context(), store)
		if err != nil {
			http.Error(w, "storage unavailable", 500)
			return
		}
		for i := range list {
			list[i].TokenHash = ""
		}
		json.NewEncoder(w).Encode(list)
		return
	}
	if r.Method == http.MethodDelete {
		var native int
		if store.db.QueryRow(`SELECT COUNT(*) FROM subscription_native_owners WHERE subscription_id=?`, r.URL.Query().Get("id")).Scan(&native) != nil || native > 0 {
			http.Error(w, "disable managed subscriptions to retain credentials and accounting history", 409)
			return
		}
		var quotaCount int
		if store.db.QueryRow(`SELECT count(*) FROM quota_accounts WHERE subscription_id=?`, r.URL.Query().Get("id")).Scan(&quotaCount) != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		if quotaCount > 0 {
			http.Error(w, "disable the subscription instead; quota ledger must be retained", 409)
			return
		}
		if _, err := store.db.Exec(`DELETE FROM subscriptions WHERE id=?`, r.URL.Query().Get("id")); err != nil {
			http.Error(w, "commit failed", 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	var input struct {
		SubscriptionRecord
		Rotate bool `json:"rotate"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid payload", 400)
		return
	}
	s := input.SubscriptionRecord
	if s.Nodes == nil {
		s.Nodes = []SubscriptionNode{}
	}
	if len(s.InboundRefs) > 0 && s.TotalLimit == nil {
		unlimited := uint64(0)
		s.TotalLimit = &unlimited
	}
	if s.TotalLimit != nil && !cfg.Quota.Coordinator {
		http.Error(w, "enable quota coordinator in server configuration first", 409)
		return
	}
	token := ""
	if r.Method == http.MethodPost {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		s.ID = hex.EncodeToString(id[:])
		if s.UpdateHours == 0 {
			s.UpdateHours = 1
		}
		input.Rotate = true
	} else {
		previous, readErr := readSubscriptions(r.Context(), store)
		if readErr != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		for _, record := range previous {
			if record.ID == s.ID && (s.Revision == "" || s.Revision != record.Revision) {
				http.Error(w, "subscription changed; reload before saving", 409)
				return
			}
		}
		var previousOwner string
		if err := store.db.QueryRow(`SELECT token_hash,user_name FROM subscriptions WHERE id=?`, s.ID).Scan(&s.TokenHash, &previousOwner); err != nil {
			http.NotFound(w, r)
			return
		}
		if previousOwner != s.User {
			var count int
			if store.db.QueryRow(`SELECT count(*) FROM quota_accounts WHERE subscription_id=?`, s.ID).Scan(&count) != nil || count > 0 {
				http.Error(w, "cannot replace the owner of a global quota subscription", 409)
				return
			}
		}
	}
	if input.Rotate {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		token = base64.RawURLEncoding.EncodeToString(secret[:])
		h := sha256.Sum256(secret[:])
		s.TokenHash = hex.EncodeToString(h[:])
	}
	owner := usersDB.Users[s.User]
	var automaticOwner *userRecord
	if r.Method == http.MethodPost && s.User == "" && len(s.InboundRefs) > 0 {
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		s.User = "sub-" + s.ID
		automaticOwner = &userRecord{Name: s.User, PBK: hex.EncodeToString(secret[:]), Enabled: true, CreatedAt: time.Now().Unix()}
		clear(secret[:])
		owner = automaticOwner
	}
	if owner == nil || validateSubscription(&s) != nil {
		http.Error(w, "invalid subscription or user", 400)
		return
	}
	if s.TotalLimit != nil {
		var bound string
		err := store.db.QueryRow(`SELECT subscription_id FROM quota_bindings WHERE user_name=?`, s.User).Scan(&bound)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "storage unavailable", 503)
			return
		}
		if err == nil && bound != s.ID {
			http.Error(w, "connection account already belongs to another subscription", 409)
			return
		}
	}
	tx, err := store.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "storage unavailable", 500)
		return
	}
	defer tx.Rollback()
	if err := validateSubscriptionInboundRefs(r.Context(), tx, s.InboundRefs); err != nil {
		http.Error(w, "invalid inbound references", 400)
		return
	}
	if automaticOwner != nil {
		if err := insertSubscriptionOwner(r.Context(), tx, automaticOwner); err != nil {
			http.Error(w, "account creation failed", 500)
			return
		}
	}
	if writeSubscription(r.Context(), tx, s) != nil || writeSubscriptionQuota(r.Context(), tx, s, owner) != nil || tx.Commit() != nil {
		http.Error(w, "commit failed", 500)
		return
	}
	if automaticOwner != nil {
		usersDB.Users[automaticOwner.Name] = automaticOwner
		store.persisted[automaticOwner.Name] = *automaticOwner
		syncStorageFromDBLocked()
	}
	if err := reloadQuotaBindingsLocked(); err != nil {
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	s.Revision = subscriptionRevision(s)
	if err := store.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM subscription_native_owners WHERE subscription_id=?)`, s.ID).Scan(&s.Managed); err != nil {
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	if s.Managed && s.Enabled {
		warmUser = s.User
	}
	s.TokenHash = ""
	link := ""
	if token != "" {
		configMu.RLock()
		base := cfg.Subscriptions.PublicURL
		configMu.RUnlock()
		link = strings.TrimRight(base, "/") + "/sub/" + token
	}
	json.NewEncoder(w).Encode(map[string]any{"subscription": s, "url": link})
}
