package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Only public, applied settings cross the control-plane boundary. A pending
// form edit must never replace the endpoint currently usable by clients.
type publicAppliedCatalog struct {
	ServerID string          `json:"server_id"`
	Revision int64           `json:"revision"`
	Inbounds []inboundRecord `json:"inbounds"`
}

type remoteInboundCatalog struct {
	PeerID string `json:"peer_id"`
	publicAppliedCatalog
}

func handleAPIAppliedInbounds(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
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
	catalog, err := store.readAppliedInboundCatalog(r.Context())
	if err != nil || catalog == nil {
		http.Error(w, "applied catalog unavailable", 409)
		return
	}
	id, err := localControlServerID(r.Context(), store.db)
	if err != nil {
		http.Error(w, "identity unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(publicAppliedCatalog{id, catalog.Revision, catalog.Inbounds})
}

func validateRemoteCatalog(c remoteInboundCatalog) error {
	if !validQuotaID(c.PeerID) || !validQuotaID(c.ServerID) || c.PeerID != strings.ToLower(c.PeerID) || c.ServerID != strings.ToLower(c.ServerID) || c.Revision < 1 || len(c.Inbounds) > 256 {
		return errors.New("invalid remote catalog")
	}
	specs := make([]InboundSpec, 0, len(c.Inbounds))
	for _, record := range c.Inbounds {
		if len(record.PublicKey) != 64 || !isValidHex(record.PublicKey) || record.PublicKey == strings.Repeat("0", 64) {
			return errors.New("invalid public key")
		}
		specs = append(specs, record.Settings)
	}
	return validateInboundSet(specs)
}

func storeRemoteCatalog(ctx context.Context, store *sqliteUserStore, input remoteInboundCatalog) error {
	if err := validateRemoteCatalog(input); err != nil {
		return err
	}
	local, err := localControlServerID(ctx, store.db)
	if err != nil {
		return err
	}
	if input.ServerID == local {
		return errors.New("cannot import local catalog")
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > 4<<20 {
		return errors.New("remote catalog too large")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var peer string
	var revision int64
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT peer_id,revision,snapshot FROM remote_inbound_catalogs WHERE server_id=?`, input.ServerID).Scan(&peer, &revision, &previous)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil {
		if peer != input.PeerID || input.Revision < revision || (input.Revision == revision && string(previous) != string(data)) {
			return errInboundConflict
		}
	} else {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM remote_inbound_catalogs`).Scan(&count); err != nil {
			return err
		}
		if count >= 256 {
			return errors.New("remote catalog limit reached")
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO remote_inbound_catalogs VALUES(?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET revision=excluded.revision,snapshot=excluded.snapshot`, input.ServerID, input.PeerID, input.Revision, data)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func handleAPIRemoteCatalogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var input remoteInboundCatalog
	if r.Method == http.MethodPost {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || validateRemoteCatalog(input) != nil {
			http.Error(w, "invalid remote catalog", 400)
			return
		}
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	if r.Method == http.MethodPost {
		if err = storeRemoteCatalog(r.Context(), store, input); err != nil {
			http.Error(w, "remote catalog conflicts with stored identity or revision", 409)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"synced": true, "server_id": input.ServerID, "revision": input.Revision})
		return
	}
	rows, err := store.db.QueryContext(r.Context(), `SELECT snapshot FROM remote_inbound_catalogs ORDER BY server_id`)
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	defer rows.Close()
	result := []remoteInboundCatalog{}
	for rows.Next() {
		var data []byte
		var item remoteInboundCatalog
		if rows.Scan(&data) != nil || len(data) > 4<<20 || json.Unmarshal(data, &item) != nil || validateRemoteCatalog(item) != nil {
			http.Error(w, "invalid stored catalog", 503)
			return
		}
		result = append(result, item)
	}
	if rows.Err() != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}
