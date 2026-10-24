package main

import (
	"database/sql"
	"net/http"
	"strings"
)

// Attach a local connection account and its profile in one transaction. An
// accounting binding alone would not make the account appear in subscriptions.
func handleAPISubscriptionAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		Subscription string `json:"subscription"`
		User         string `json:"user"`
		Node         int    `json:"node"` // one-based endpoint selected by the administrator
	}
	if !decodeQuotaJSON(w, r, &input) {
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	if !validQuotaID(input.Subscription) || !isValidUsername(input.User) || input.Node < 1 || usersDB.Users[input.User] == nil {
		http.Error(w, "invalid subscription account", 400)
		return
	}
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	quotaState.RLock()
	worker := quotaState.worker
	quotaState.RUnlock()
	if !cfg.Quota.Coordinator || worker == nil || worker.store != store {
		http.Error(w, "quota coordinator not configured", 409)
		return
	}
	records, err := readSubscriptions(r.Context(), store)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	var subscription *SubscriptionRecord
	for i := range records {
		if records[i].ID == input.Subscription {
			subscription = &records[i]
			break
		}
	}
	if subscription == nil || input.Node > len(subscription.Nodes) {
		http.Error(w, "subscription endpoint not found", 404)
		return
	}
	if subscription.TotalLimit == nil {
		http.Error(w, "enable a shared subscription quota before attaching accounts", 409)
		return
	}
	node := subscription.Nodes[input.Node-1]
	if getServerStaticPubHex() == "" || !strings.EqualFold(node.ServerPubKey, getServerStaticPubHex()) {
		http.Error(w, "selected endpoint belongs to another server; attach the account on that server", 409)
		return
	}
	account := usersDB.Users[input.User]
	node.User, node.PBK = account.Name, account.PBK
	node.Name = account.Name + " · " + node.Name
	if len(node.Name) > 256 {
		node.Name = account.Name
	}
	found := false
	for _, previous := range subscription.Nodes {
		user := previous.User
		if user == "" {
			user = subscription.User
		}
		if user == input.User && previous.Server == node.Server && previous.ServerPubKey == node.ServerPubKey && previous.SNI == node.SNI && previous.WireVersion == node.WireVersion {
			found = true
			break
		}
	}
	if !found {
		subscription.Nodes = append(subscription.Nodes, node)
	}
	if validateSubscription(subscription) != nil {
		http.Error(w, "subscription profile limit reached or invalid account", 400)
		return
	}
	tx, err := store.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	defer tx.Rollback()
	var previous string
	err = tx.QueryRow(`SELECT subscription_id FROM quota_bindings WHERE user_name=?`, input.User).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "storage unavailable", 503)
		return
	}
	if err == nil && previous != input.Subscription {
		http.Error(w, "account already belongs to another subscription", 409)
		return
	}
	if _, err = tx.Exec(`INSERT INTO quota_bindings VALUES(?,?) ON CONFLICT(user_name) DO NOTHING`, input.User, input.Subscription); err != nil {
		http.Error(w, "commit failed", 500)
		return
	}
	if writeSubscription(r.Context(), tx, *subscription) != nil || tx.Commit() != nil {
		http.Error(w, "commit failed", 500)
		return
	}
	if reloadQuotaBindingsLocked() != nil {
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	_, _ = w.Write([]byte(`{"success":true}`))
}
