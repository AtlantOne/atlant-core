package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

type ClientGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Note     string   `json:"note"`
	Revision int64    `json:"revision"`
	Users    []string `json:"users"`
	Up       uint64   `json:"up_bytes"`
	Down     uint64   `json:"down_bytes"`
	Online   int      `json:"online_users"`
}

func createClientGroupTables(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS client_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE,note TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS client_group_members(user_name TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,group_id TEXT NOT NULL REFERENCES client_groups(id) ON DELETE CASCADE);
CREATE INDEX IF NOT EXISTS client_group_members_group ON client_group_members(group_id);`)
	return err
}

func validGroupName(name, note string) bool {
	if name == "" || strings.TrimSpace(name) != name || len(name) > 160 || len(note) > 4096 {
		return false
	}
	for _, char := range name {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

// Caller holds usersMu: metadata comes from SQLite, current counters from RAM.
func readClientGroups(ctx context.Context, store *sqliteUserStore) ([]ClientGroup, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id,name,note,revision FROM client_groups ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	result := []ClientGroup{}
	indices := map[string]int{}
	for rows.Next() {
		var group ClientGroup
		group.Users = []string{}
		if err = rows.Scan(&group.ID, &group.Name, &group.Note, &group.Revision); err != nil {
			rows.Close()
			return nil, err
		}
		indices[group.ID] = len(result)
		result = append(result, group)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = store.db.QueryContext(ctx, `SELECT user_name,group_id FROM client_group_members ORDER BY user_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user, id string
		if err = rows.Scan(&user, &id); err != nil {
			return nil, err
		}
		index, ok := indices[id]
		account := usersDB.Users[user]
		if !ok || account == nil {
			continue
		}
		group := &result[index]
		group.Users = append(group.Users, user)
		group.Up = totalTraffic(group.Up, atomic.LoadUint64(&account.UpBytes))
		group.Down = totalTraffic(group.Down, atomic.LoadUint64(&account.DownBytes))
		if getUserActiveConns(user) > 0 {
			group.Online++
		}
	}
	return result, rows.Err()
}

var errGroupConflict = errors.New("group changed; reload before saving")

func handleAPIClientGroups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
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
		groups, err := readClientGroups(r.Context(), store)
		if err != nil {
			http.Error(w, "storage unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(groups)
		return
	}
	var input struct {
		ID       string    `json:"id"`
		Name     string    `json:"name"`
		Note     string    `json:"note"`
		Revision int64     `json:"revision"`
		Users    *[]string `json:"users,omitempty"`
	}
	if !decodeQuotaJSON(w, r, &input) {
		return
	}
	if r.Method == http.MethodPost {
		input.ID = quotaID()
		input.Revision = 0
	}
	if !validQuotaID(input.ID) || (r.Method != http.MethodDelete && !validGroupName(input.Name, input.Note)) || input.Revision < 0 || (r.Method != http.MethodPost && input.Revision < 1) {
		http.Error(w, "invalid group", 400)
		return
	}
	if input.Users != nil {
		if len(*input.Users) > 10000 {
			http.Error(w, "too many group members", 400)
			return
		}
		seen := map[string]bool{}
		for _, name := range *input.Users {
			if !isValidUsername(name) || usersDB.Users[name] == nil || seen[name] {
				http.Error(w, "invalid or duplicate group member", 400)
				return
			}
			seen[name] = true
		}
	}
	tx, err := store.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	defer tx.Rollback()
	var mutation sql.Result
	switch r.Method {
	case http.MethodPost:
		mutation, err = tx.Exec(`INSERT INTO client_groups VALUES(?,?,?,1,?)`, input.ID, input.Name, input.Note, time.Now().Unix())
	case http.MethodPut:
		mutation, err = tx.Exec(`UPDATE client_groups SET name=?,note=?,revision=revision+1 WHERE id=? AND revision=?`, input.Name, input.Note, input.ID, input.Revision)
	case http.MethodDelete:
		mutation, err = tx.Exec(`DELETE FROM client_groups WHERE id=? AND revision=?`, input.ID, input.Revision)
	}
	if err != nil {
		http.Error(w, "group name already exists or storage rejected the change", 409)
		return
	}
	if count, err := mutation.RowsAffected(); err != nil || count != 1 {
		http.Error(w, errGroupConflict.Error(), 409)
		return
	}
	if input.Users != nil && r.Method != http.MethodDelete {
		// Explicit moves update the old group's revision as well, invalidating
		// open editors that otherwise could silently steal memberships back.
		for _, user := range *input.Users {
			if _, err = tx.Exec(`UPDATE client_groups SET revision=revision+1 WHERE id IN (SELECT group_id FROM client_group_members WHERE user_name=? AND group_id<>?)`, user, input.ID); err != nil {
				break
			}
		}
		if err == nil {
			_, err = tx.Exec(`DELETE FROM client_group_members WHERE group_id=?`, input.ID)
		}
		if err == nil {
			for _, user := range *input.Users {
				_, err = tx.Exec(`INSERT INTO client_group_members VALUES(?,?) ON CONFLICT(user_name) DO UPDATE SET group_id=excluded.group_id`, user, input.ID)
				if err != nil {
					break
				}
			}
		}
	}
	if err != nil || tx.Commit() != nil {
		http.Error(w, "group update rolled back", 500)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": input.ID, "success": true})
}
