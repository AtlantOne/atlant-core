package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

func decodeQuotaJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		http.Error(w, "invalid payload", 400)
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "invalid payload", 400)
		return false
	}
	return true
}

// Separate node credentials authorize only the quota RPC and explicitly
// assigned subscriptions. They never authorize management API access.
func handleQuotaBudget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || cfg == nil || !cfg.Quota.Coordinator {
		http.NotFound(w, r)
		return
	}
	node := r.Header.Get("X-Atlant-Node")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !quotaNodeName(node) || len(token) != 64 || !isValidHex(token) {
		http.NotFound(w, r)
		return
	}
	h := sha256.Sum256([]byte(token))
	usersMu.RLock()
	store := currentUsersStore
	usersMu.RUnlock()
	if store == nil {
		http.NotFound(w, r)
		return
	}
	var ok int
	if store.db.QueryRowContext(r.Context(), `SELECT 1 FROM quota_nodes WHERE id=? AND token_hash=? AND enabled=1`, node, hex.EncodeToString(h[:])).Scan(&ok) != nil {
		http.NotFound(w, r)
		return
	}
	var request quotaRequest
	if !decodeQuotaJSON(w, r, &request) {
		return
	}
	reply, err := processQuota(r.Context(), store.db, node, request, time.Now())
	if err != nil {
		if errors.Is(err, errQuotaClock) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "clock"})
			return
		}
		http.Error(w, "quota request rejected", 409)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

// Registered behind the existing authenticated admin API middleware.
func handleAPIQuotaNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if cfg == nil || !cfg.Quota.Coordinator {
		http.Error(w, "coordinator not enabled", 409)
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	if r.Method == http.MethodGet {
		rows, err := store.db.Query(`SELECT id,enabled FROM quota_nodes ORDER BY id`)
		if err != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		list := []map[string]any{}
		for rows.Next() {
			var id string
			var enabled bool
			if rows.Scan(&id, &enabled) != nil {
				rows.Close()
				http.Error(w, "storage unavailable", 503)
				return
			}
			list = append(list, map[string]any{"id": id, "enabled": enabled})
		}
		if rows.Err() != nil {
			rows.Close()
			http.Error(w, "storage unavailable", 503)
			return
		}
		rows.Close()
		// Materialize node rows first: this store has one SQLite connection.
		for _, node := range list {
			assigned, err := store.db.Query(`SELECT subscription_id FROM quota_node_subscriptions WHERE node_id=? ORDER BY subscription_id`, node["id"])
			if err != nil {
				http.Error(w, "storage unavailable", 503)
				return
			}
			subscriptions := []string{}
			for assigned.Next() {
				var id string
				if err = assigned.Scan(&id); err != nil {
					break
				}
				subscriptions = append(subscriptions, id)
			}
			if err == nil {
				err = assigned.Err()
			}
			assigned.Close()
			if err != nil {
				http.Error(w, "storage unavailable", 503)
				return
			}
			node["subscriptions"] = subscriptions
		}
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		ID            string   `json:"id"`
		Subscriptions []string `json:"subscriptions"`
		Enabled       bool     `json:"enabled"`
	}
	if !decodeQuotaJSON(w, r, &input) {
		return
	}
	if !quotaNodeName(input.ID) || len(input.Subscriptions) > 10000 {
		http.Error(w, "invalid node", 400)
		return
	}
	for _, id := range input.Subscriptions {
		if !validQuotaID(id) {
			http.Error(w, "invalid subscription", 400)
			return
		}
	}
	if r.Method == http.MethodDelete {
		_, err = store.db.Exec(`UPDATE quota_nodes SET enabled=0 WHERE id=?`, input.ID)
		if err != nil {
			http.Error(w, "commit failed", 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		return
	}
	tx, err := store.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	defer tx.Rollback()
	secret := ""
	if r.Method == http.MethodPost {
		var raw [32]byte
		if _, err = rand.Read(raw[:]); err != nil {
			http.Error(w, "entropy unavailable", 500)
			return
		}
		secret = hex.EncodeToString(raw[:])
		h := sha256.Sum256([]byte(secret))
		_, err = tx.Exec(`INSERT INTO quota_nodes VALUES(?,?,?)`, input.ID, hex.EncodeToString(h[:]), input.Enabled)
	} else {
		var result sql.Result
		result, err = tx.Exec(`UPDATE quota_nodes SET enabled=? WHERE id=?`, input.Enabled, input.ID)
		if err == nil {
			n, _ := result.RowsAffected()
			if n != 1 {
				http.NotFound(w, r)
				return
			}
		}
	}
	if err == nil {
		_, err = tx.Exec(`DELETE FROM quota_node_subscriptions WHERE node_id=?`, input.ID)
	}
	if err == nil {
		for _, id := range input.Subscriptions {
			if _, err = tx.Exec(`INSERT OR IGNORE INTO quota_node_subscriptions VALUES(?,?)`, input.ID, id); err != nil {
				break
			}
		}
	}
	if err != nil || tx.Commit() != nil {
		http.Error(w, "commit failed", 409)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": input.ID, "token": secret, "enabled": input.Enabled})
}

func handleAPIQuotaBindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	if r.Method == http.MethodGet {
		rows, err := store.db.Query(`SELECT user_name,subscription_id FROM quota_bindings ORDER BY user_name`)
		if err != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		defer rows.Close()
		list := []map[string]string{}
		for rows.Next() {
			var name, id string
			if rows.Scan(&name, &id) != nil {
				http.Error(w, "storage unavailable", 503)
				return
			}
			list = append(list, map[string]string{"user": name, "subscription": id})
		}
		if rows.Err() != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(list)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		User         string `json:"user"`
		Subscription string `json:"subscription"`
	}
	if !decodeQuotaJSON(w, r, &input) {
		return
	}
	if !isValidUsername(input.User) || usersDB.Users[input.User] == nil || !validQuotaID(input.Subscription) {
		http.Error(w, "invalid binding", 400)
		return
	}
	var remote int
	if err := store.db.QueryRow(`SELECT count(*) FROM remote_accounts WHERE user_name=?`, input.User).Scan(&remote); err != nil || remote != 0 {
		http.Error(w, "remote accounts require their assigned coordinator route", 409)
		return
	}
	quotaState.RLock()
	worker := quotaState.worker
	quotaState.RUnlock()
	if worker == nil || worker.store != store {
		http.Error(w, "quota worker not configured", 409)
		return
	}
	if cfg.Quota.Coordinator {
		if _, err = readQuota(r.Context(), store.db, input.Subscription); err != nil {
			http.Error(w, "unknown subscription", 400)
			return
		}
	}
	// Rebinding requires explicit removal/migration; it cannot silently reset
	// the billing identity of an established connection account.
	var previous string
	err = store.db.QueryRow(`SELECT subscription_id FROM quota_bindings WHERE user_name=?`, input.User).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "storage unavailable", 503)
		return
	}
	if err == nil && previous != input.Subscription {
		http.Error(w, "account already belongs to another subscription", 409)
		return
	}
	if _, err = store.db.Exec(`INSERT INTO quota_bindings VALUES(?,?) ON CONFLICT(user_name) DO UPDATE SET subscription_id=excluded.subscription_id`, input.User, input.Subscription); err != nil {
		http.Error(w, "commit failed", 500)
		return
	}
	if reloadQuotaBindingsLocked() != nil {
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	// Existing flows also use recordUserTraffic and observe the new budget.
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
