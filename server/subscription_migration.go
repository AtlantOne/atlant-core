package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type subscriptionMigrationItem struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Converted  int      `json:"converted_profiles"`
	Preserved  int      `json:"preserved_profiles"`
	InboundIDs []string `json:"inbound_ids"`
	Blockers   []string `json:"blockers"`
	Eligible   bool     `json:"eligible"`
	next       SubscriptionRecord
}
type subscriptionMigrationPlan struct {
	Revision string                      `json:"revision"`
	Items    []subscriptionMigrationItem `json:"items"`
}

func migrationEndpoint(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.FormatUint(p, 10))
}

// Caller owns usersMu. Plans contain no access keys; the digest also binds
// private owner settings so they cannot change between preview and commit.
func planSubscriptionMigration(ctx context.Context, store *sqliteUserStore) (subscriptionMigrationPlan, error) {
	plan := subscriptionMigrationPlan{Items: []subscriptionMigrationItem{}}
	catalog, err := store.readAppliedInboundCatalog(ctx)
	if err != nil {
		return plan, err
	}
	if catalog == nil {
		return plan, errors.New("applied inbound catalog required")
	}
	saved, err := store.readInboundCatalog(ctx)
	if err != nil {
		return plan, err
	}
	if saved.Revision != catalog.Revision {
		return plan, errors.New("apply pending inbound changes before migration")
	}
	local, err := localControlServerID(ctx, store.db)
	if err != nil {
		return plan, err
	}
	records, err := readSubscriptions(ctx, store)
	if err != nil {
		return plan, err
	}
	owners := map[string]int{}
	for _, s := range records {
		owners[s.User]++
	}
	hash := sha256.New()
	fingerprint := json.NewEncoder(hash)
	fingerprint.Encode([]any{local, catalog.Revision, cfg.Quota.Coordinator})
	for _, s := range records {
		owner := usersDB.Users[s.User]
		fingerprint.Encode(s.Revision)
		if owner == nil {
			continue
		}
		fingerprint.Encode([]any{owner.Name, owner.PBK, owner.Enabled, owner.TotalLimit, owner.ExpiresAt, owner.IPLimit, owner.Note})
		if len(s.Nodes) == 0 {
			continue
		}
		item := subscriptionMigrationItem{ID: s.ID, Title: s.Title, InboundIDs: []string{}, Blockers: []string{}, next: s}
		item.next.Nodes = []SubscriptionNode{}
		item.next.InboundRefs = append([]SubscriptionInboundRef(nil), s.InboundRefs...)
		seen := map[string]bool{}
		for _, ref := range s.InboundRefs {
			if ref.ServerID == local {
				seen[ref.InboundID] = true
			}
		}
		for _, node := range s.Nodes {
			var matches []inboundRecord
			localEndpoint := false
			for _, record := range catalog.Inbounds {
				if migrationEndpoint(node.Server) != "" && migrationEndpoint(node.Server) == migrationEndpoint(record.Settings.AdvertiseAddr) {
					localEndpoint = true
				}
				if record.Settings.Enabled && migrationEndpoint(node.Server) != "" && migrationEndpoint(node.Server) == migrationEndpoint(record.Settings.AdvertiseAddr) &&
					strings.EqualFold(node.ServerPubKey, record.PublicKey) && strings.EqualFold(node.SNI, record.Settings.SNI) && node.WireVersion == record.Settings.WireVersion &&
					(node.User == "" || node.User == s.User) && (node.PBK == "" || strings.EqualFold(node.PBK, owner.PBK)) {
					transport := node.Transport
					if transport == "reality" {
						transport = "tcp"
					}
					for _, available := range record.Settings.Transports {
						if available == transport {
							matches = append(matches, record)
							break
						}
					}
				}
			}
			if len(matches) != 1 {
				item.next.Nodes = append(item.next.Nodes, node)
				item.Preserved++
				if len(matches) > 1 {
					item.Blockers = append(item.Blockers, "migration_ambiguous_inbound")
				}
				if len(matches) == 0 && localEndpoint && (node.User == "" || node.User == s.User) {
					item.Blockers = append(item.Blockers, "migration_unmatched_local")
				}
				continue
			}
			id := matches[0].Settings.ID
			item.Converted++
			if !seen[id] {
				seen[id] = true
				item.InboundIDs = append(item.InboundIDs, id)
				item.next.InboundRefs = append(item.next.InboundRefs, SubscriptionInboundRef{ServerID: local, InboundID: id})
			}
		}
		if item.Converted == 0 {
			continue
		}
		if owners[s.User] != 1 {
			item.Blockers = append(item.Blockers, "migration_shared_owner")
		}
		if !cfg.Quota.Coordinator {
			item.Blockers = append(item.Blockers, "migration_coordinator_required")
		}
		if !s.Managed && s.TotalLimit != nil && owner.TotalLimit > 0 && *s.TotalLimit != owner.TotalLimit {
			item.Blockers = append(item.Blockers, "migration_conflicting_quota")
		}
		if owner.IPLimit < 0 || owner.IPLimit > 10000 || len(owner.Note) > 4096 {
			item.Blockers = append(item.Blockers, "migration_invalid_policy")
		}
		if owner.TotalLimit > uint64(quotaMaxValue) || owner.UpBytes > uint64(quotaMaxValue) || owner.DownBytes > uint64(quotaMaxValue) || totalTraffic(owner.UpBytes, owner.DownBytes) > uint64(quotaMaxValue) {
			item.Blockers = append(item.Blockers, "migration_quota_range")
		}
		var bound string
		if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(subscription_id),'') FROM quota_bindings WHERE user_name=?`, s.User).Scan(&bound); err != nil {
			return plan, err
		}
		if bound != "" && bound != s.ID {
			item.Blockers = append(item.Blockers, "migration_shared_owner")
		}
		if item.next.TotalLimit == nil {
			limit := owner.TotalLimit
			item.next.TotalLimit = &limit
		}
		if !s.Managed {
			item.next.Enabled = s.Enabled && owner.Enabled
			if owner.ExpiresAt > 0 && (s.ExpiresAt == 0 || owner.ExpiresAt < s.ExpiresAt) {
				item.next.ExpiresAt = owner.ExpiresAt
			}
			item.next.IPLimit, item.next.Note = owner.IPLimit, owner.Note
		}
		item.Eligible = len(item.Blockers) == 0
		plan.Items = append(plan.Items, item)
	}
	plan.Revision = hex.EncodeToString(hash.Sum(nil))
	return plan, nil
}

func handleAPISubscriptionMigration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input struct {
		Revision string   `json:"revision"`
		IDs      []string `json:"ids"`
	}
	if r.Method == http.MethodPost {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
		d.DisallowUnknownFields()
		if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || len(input.IDs) == 0 || len(input.IDs) > 100 {
			http.Error(w, "invalid migration request", 400)
			return
		}
	}
	usersMu.Lock()
	previous := subscriptionAccess.Load()
	var warm []string
	defer func() {
		usersMu.Unlock()
		for _, name := range changedSubscriptionAccess(previous, subscriptionAccess.Load()) {
			kickUserSessions(name)
		}
		for _, name := range warm {
			primeQuotaUser(name)
		}
	}()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	plan, err := planSubscriptionMigration(r.Context(), store)
	if err != nil {
		http.Error(w, "migration plan unavailable", 503)
		return
	}
	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(plan)
		return
	}
	if input.Revision != plan.Revision {
		http.Error(w, "migration plan changed; reload", 409)
		return
	}
	selected := map[string]subscriptionMigrationItem{}
	for _, id := range input.IDs {
		if _, duplicate := selected[id]; duplicate {
			http.Error(w, "duplicate migration ID", 400)
			return
		}
		found := false
		for _, item := range plan.Items {
			if item.ID == id && item.Eligible {
				selected[id] = item
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "subscription cannot be migrated", 409)
			return
		}
	}
	tx, err := store.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	defer tx.Rollback()
	for _, id := range input.IDs {
		item := selected[id]
		s := item.next
		owner := usersDB.Users[s.User]
		if err = writeSubscription(r.Context(), tx, s); err == nil {
			err = writeSubscriptionQuota(r.Context(), tx, s, owner)
		}
		if err == nil && !s.Managed {
			_, err = tx.ExecContext(r.Context(), `UPDATE users SET enabled=1,total_limit='0',expires_at=0,up_bytes=?,down_bytes=? WHERE name=?`, strconv.FormatUint(owner.UpBytes, 10), strconv.FormatUint(owner.DownBytes, 10), owner.Name)
		}
		if err != nil {
			http.Error(w, "migration failed; nothing changed", 500)
			return
		}
	}
	if tx.Commit() != nil {
		http.Error(w, "migration commit failed", 500)
		return
	}
	for _, id := range input.IDs {
		s := selected[id].next
		owner := usersDB.Users[s.User]
		if !s.Managed {
			owner.Enabled = true
			owner.TotalLimit = 0
			owner.ExpiresAt = 0
			store.persisted[owner.Name] = *owner
		}
		if s.Enabled {
			warm = append(warm, s.User)
		}
	}
	syncStorageFromDBLocked()
	if reloadQuotaBindingsLocked() != nil {
		http.Error(w, "reload failed; restart required", 503)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"success": true, "migrated": len(selected)})
}
