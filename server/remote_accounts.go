package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type remoteAccountInput struct {
	Owner        string   `json:"owner_panel"`
	Subscription string   `json:"subscription_id"`
	Revision     int64    `json:"revision"`
	Enabled      bool     `json:"enabled"`
	Expires      int64    `json:"expires_at"`
	IPLimit      int      `json:"ip_limit"`
	Inbounds     []string `json:"inbounds"`
	Endpoint     string   `json:"endpoint"`
	NodeID       string   `json:"node_id"`
	NodeToken    string   `json:"node_token"`
}

func remoteQuotaEndpoint(value string) bool {
	p, err := url.Parse(value)
	return err == nil && p.Scheme == "https" && p.Hostname() != "" && p.User == nil && p.Path == "" && p.RawQuery == "" && p.Fragment == "" && !strings.ContainsAny(value, "\r\n")
}

func (input remoteAccountInput) validate() error {
	if !validQuotaID(input.Owner) || input.Owner != strings.ToLower(input.Owner) || !validQuotaID(input.Subscription) || input.Subscription != strings.ToLower(input.Subscription) || input.Revision < 0 || input.Revision >= math.MaxInt64 || input.Expires < 0 || input.IPLimit < 0 || input.IPLimit > 10000 || len(input.Inbounds) == 0 || len(input.Inbounds) > 256 || !remoteQuotaEndpoint(input.Endpoint) || !quotaNodeName(input.NodeID) || len(input.NodeToken) != 64 || !isValidHex(input.NodeToken) {
		return errors.New("invalid remote account")
	}
	seen := map[string]bool{}
	for _, id := range input.Inbounds {
		if !inboundIDPattern.MatchString(id) || seen[id] {
			return errors.New("invalid remote inbound scope")
		}
		seen[id] = true
	}
	return nil
}

func remoteAccountName(owner, subscription string) string {
	sum := sha256.Sum256([]byte(owner + ":" + subscription))
	return "peer-" + hex.EncodeToString(sum[:16])
}

// There is deliberately no quota_accounts row on this follower. The global
// subscription ledger remains on its coordinator; this account only reserves
// bounded credit through a dedicated, subscription-scoped node credential.
func putRemoteAccount(ctx context.Context, store *sqliteUserStore, input remoteAccountInput) (*userRecord, int64, error) {
	if err := input.validate(); err != nil {
		return nil, 0, err
	}
	applied, err := store.readAppliedInboundCatalog(ctx)
	if err != nil || applied == nil {
		return nil, 0, errors.New("applied catalog unavailable")
	}
	available := map[string]bool{}
	for _, record := range applied.Inbounds {
		available[record.Settings.ID] = true
	}
	for _, id := range input.Inbounds {
		if !available[id] {
			return nil, 0, errors.New("unknown applied inbound")
		}
	}
	name := remoteAccountName(input.Owner, input.Subscription)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer tx.Rollback()
	var old int64
	var storedName string
	err = tx.QueryRowContext(ctx, `SELECT revision,user_name FROM remote_accounts WHERE owner_panel=? AND subscription_id=?`, input.Owner, input.Subscription).Scan(&old, &storedName)
	created := err == sql.ErrNoRows
	if err != nil && !created {
		return nil, 0, err
	}
	if (!created && (old != input.Revision || storedName != name)) || (created && input.Revision != 0) {
		return nil, 0, errInboundConflict
	}
	u := usersDB.Users[name]
	if created {
		if u != nil {
			return nil, 0, errors.New("remote account name collision")
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM remote_accounts`).Scan(&count); err != nil {
			return nil, 0, err
		}
		if count >= 10000 {
			return nil, 0, errors.New("remote account limit reached")
		}
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			return nil, 0, err
		}
		u = &userRecord{Name: name, PBK: hex.EncodeToString(key[:]), Enabled: true, CreatedAt: time.Now().Unix()}
		clear(key[:])
		if err := insertSubscriptionOwner(ctx, tx, u); err != nil {
			return nil, 0, err
		}
	} else if u == nil {
		return nil, 0, errors.New("remote account missing")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO remote_accounts VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_panel,subscription_id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,expires_at=excluded.expires_at,ip_limit=excluded.ip_limit,endpoint=excluded.endpoint,node_id=excluded.node_id,node_token=excluded.node_token`, input.Owner, input.Subscription, name, input.Revision+1, input.Enabled, input.Expires, input.IPLimit, input.Endpoint, input.NodeID, input.NodeToken)
	if err != nil {
		return nil, 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM remote_account_inbounds WHERE owner_panel=? AND subscription_id=?`, input.Owner, input.Subscription); err != nil {
		return nil, 0, err
	}
	for _, id := range input.Inbounds {
		if _, err = tx.ExecContext(ctx, `INSERT INTO remote_account_inbounds VALUES(?,?,?)`, input.Owner, input.Subscription, id); err != nil {
			return nil, 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, 0, err
	}
	if created {
		usersDB.Users[name] = u
		store.persisted[name] = *u
		syncStorageFromDBLocked()
	}
	return u, input.Revision + 1, nil
}

func loadRemoteAccess(ctx context.Context, store *sqliteUserStore, index *subscriptionAccessIndex) error {
	rows, err := store.db.QueryContext(ctx, `SELECT a.user_name,a.owner_panel,a.subscription_id,a.enabled,a.expires_at,a.ip_limit,r.inbound_id FROM remote_accounts a LEFT JOIN remote_account_inbounds r ON r.owner_panel=a.owner_panel AND r.subscription_id=a.subscription_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, owner, sub string
		var enabled bool
		var expires int64
		var ipLimit int
		var inbound sql.NullString
		if err := rows.Scan(&name, &owner, &sub, &enabled, &expires, &ipLimit, &inbound); err != nil {
			return err
		}
		id := "remote:" + owner + ":" + sub
		access, exists := index.Users[name]
		if exists && access.ID != id {
			return errors.New("ambiguous remote account owner")
		}
		if !exists {
			access = subscriptionUserAccess{ID: id, Enabled: enabled, Expires: expires, IPLimit: ipLimit, Inbounds: map[string]bool{}, RequireQuota: true}
		}
		if inbound.Valid {
			access.Inbounds[inbound.String] = true
		}
		index.Users[name] = access
	}
	return rows.Err()
}

// Called under usersMu and w.mu; no network requests take place while loading.
func loadRemoteBudgets(w *quotaWorker, users map[string]*nodeBudget) error {
	rows, err := w.store.db.Query(`SELECT owner_panel,subscription_id,user_name,enabled,endpoint,node_id,node_token FROM remote_accounts`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var owner, sub, name, endpoint, node, token string
		var enabled bool
		if err := rows.Scan(&owner, &sub, &name, &enabled, &endpoint, &node, &token); err != nil {
			return err
		}
		if !remoteQuotaEndpoint(endpoint) || !quotaNodeName(node) || len(token) != 64 || !isValidHex(token) {
			return errors.New("invalid stored remote quota route")
		}
		if _, exists := users[name]; exists {
			return errors.New("remote account has a conflicting local quota binding")
		}
		if !enabled {
			continue
		}
		source := sha256.Sum256([]byte(endpoint + "\x00" + node + "\x00" + token))
		key := "remote:" + owner + ":" + sub + ":" + hex.EncodeToString(source[:])
		b := w.budgets[key]
		if b == nil {
			if len(w.budgets) >= 20000 {
				return errors.New("quota route limit reached")
			}
			client := &http.Client{Timeout: quotaRefreshTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			b = &nodeBudget{subscription: sub, session: w.session, call: remoteQuotaCall(endpoint+"/quota/v1/budget", node, token, client), stop: w.stop}
			w.budgets[key] = b
		}
		users[name] = b
	}
	return rows.Err()
}

func handleAPIRemoteAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		readAPIRemoteAccount(w, r)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input remoteAccountInput
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || input.validate() != nil {
		http.Error(w, "invalid remote account", 400)
		return
	}
	usersMu.Lock()
	previous := subscriptionAccess.Load()
	warm := ""
	defer func() {
		usersMu.Unlock()
		for _, name := range changedSubscriptionAccess(previous, subscriptionAccess.Load()) {
			kickUserSessions(name)
		}
		if warm != "" {
			primeQuotaUser(warm)
		}
	}()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	quotaState.RLock()
	worker := quotaState.worker
	quotaState.RUnlock()
	if worker == nil || worker.store != store {
		http.Error(w, "quota worker unavailable", 409)
		return
	}
	u, revision, err := putRemoteAccount(r.Context(), store, input)
	if err != nil {
		http.Error(w, "remote account conflict or invalid inbound scope", 409)
		return
	}
	if err := reloadQuotaBindingsLocked(); err != nil {
		subscriptionAccess.Store(&subscriptionAccessIndex{Blocked: true})
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	if input.Enabled {
		warm = u.Name
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"user": u.Name, "pbk": u.PBK, "revision": revision})
}

func readAPIRemoteAccount(w http.ResponseWriter, r *http.Request) {
	owner, sub := r.URL.Query().Get("owner_panel"), r.URL.Query().Get("subscription_id")
	if !validQuotaID(owner) || !validQuotaID(sub) {
		http.Error(w, "invalid remote account", 400)
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	var name string
	var revision int64
	if err := store.db.QueryRowContext(r.Context(), `SELECT user_name,revision FROM remote_accounts WHERE owner_panel=? AND subscription_id=?`, owner, sub).Scan(&name, &revision); err != nil {
		http.NotFound(w, r)
		return
	}
	u := usersDB.Users[name]
	if u == nil {
		http.Error(w, "account unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"user": name, "pbk": u.PBK, "revision": revision})
}
