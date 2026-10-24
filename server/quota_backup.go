package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// Includes the complete ledger and active reservations. Recovery is deliberately
// offline: replaying an old snapshot while nodes keep serving would reset quota.
func handleAPISQLiteBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "storage unavailable", 503)
		return
	}
	if err = saveUsersLocked(cfg.UsersFile, usersDB); err != nil {
		usersMu.Unlock()
		http.Error(w, "checkpoint failed", 503)
		return
	}
	dir, err := os.MkdirTemp(filepath.Dir(store.path), ".atlant-backup-")
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "snapshot unavailable", 503)
		return
	}
	defer os.RemoveAll(dir) // Exact private directory returned by MkdirTemp.
	path := filepath.Join(dir, "snapshot.db")
	_, err = store.db.ExecContext(r.Context(), `VACUUM INTO ?`, path)
	usersMu.Unlock()
	if err != nil {
		http.Error(w, "snapshot failed", 503)
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > 32<<20 {
		http.Error(w, "use a local SQLite backup for databases over 32 MiB", 413)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "snapshot unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="atlant-sqlite-backup.json"`)
	_ = json.NewEncoder(w).Encode(struct {
		Format   string `json:"format"`
		Database []byte `json:"database"`
		Recovery string `json:"recovery"`
	}{"sqlite3-base64-v1", data, "coordinated-offline-only"})
}
