package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
)

var inboundAdministrationMu sync.Mutex

func handleAPIInbounds(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		handleInboundMutation(w, r)
		return
	}
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	catalog, err := store.readInboundCatalog(r.Context())
	var serverID string
	if err == nil {
		serverID, err = localControlServerID(r.Context(), store.db)
	}
	usersMu.Unlock()
	if err != nil {
		http.Error(w, "inbound catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	var applied int64
	running := false
	active := []string{}
	if runtime := activeInboundSet.Load(); runtime != nil {
		applied = runtime.revision
		running = runtime.ctx.Err() == nil
		if running {
			for _, binding := range runtime.bindings {
				active = append(active, binding.record.Settings.ID)
			}
		}
	}
	_ = json.NewEncoder(w).Encode(struct {
		inboundCatalog
		AppliedRevision int64    `json:"applied_revision"`
		Active          []string `json:"active"`
		Running         bool     `json:"running"`
		Editable        bool     `json:"editable"`
		CanApply        bool     `json:"can_apply"`
		ServerID        string   `json:"server_id"`
	}{catalog, applied, active, running, catalog.Initialized, activeInboundController.Load() != nil, serverID})
}

func handleInboundMutation(w http.ResponseWriter, r *http.Request) {
	apply := r.URL.Path == "/api/inbounds/apply"
	if (apply && r.Method != http.MethodPost) || (!apply && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Revision int64        `json:"revision"`
		Settings *InboundSpec `json:"settings,omitempty"`
		ID       string       `json:"id,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Revision < 1 || decoder.Decode(new(any)) != io.EOF || (apply && (input.Settings != nil || input.ID != "")) || (!apply && r.Method != http.MethodDelete && (input.Settings == nil || input.ID != "")) || (!apply && r.Method == http.MethodDelete && (input.Settings != nil || !inboundIDPattern.MatchString(input.ID))) {
		http.Error(w, "invalid inbound request", http.StatusBadRequest)
		return
	}
	if input.Settings != nil {
		if err := input.Settings.validate(); err != nil {
			http.Error(w, "invalid inbound settings", http.StatusBadRequest)
			return
		}
	}
	inboundAdministrationMu.Lock()
	defer inboundAdministrationMu.Unlock()
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	catalog, err := store.readInboundCatalog(r.Context())
	if err == nil {
		err = checkInboundRevision(catalog, input.Revision)
	}
	if err != nil {
		usersMu.Unlock()
		http.Error(w, "inbound catalog changed or unavailable; reload before saving", http.StatusConflict)
		return
	}
	if apply {
		// Closing active sessions can require usersMu. Never hold it during apply.
		usersMu.Unlock()
		controller := activeInboundController.Load()
		if controller == nil {
			http.Error(w, "native inbound controller is unavailable", http.StatusConflict)
			return
		}
		rolledBack, err := controller.Apply(catalog)
		if err != nil {
			log.Printf("[INBOUNDS] Apply revision %d failed (runtime restored=%t): %v", catalog.Revision, rolledBack, err)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "inbound_apply_failed", "runtime_restored": rolledBack, "saved_revision": catalog.Revision})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"applied_revision": catalog.Revision, "applied": true})
		return
	}
	defer usersMu.Unlock()
	// Until flat subscription profiles have been migrated to stable references,
	// protect listeners they still depend on. Deletion must not orphan links.
	if r.Method == http.MethodDelete {
		var publicKey string
		for _, record := range catalog.Inbounds {
			if record.Settings.ID == input.ID {
				publicKey = record.PublicKey
			}
		}
		var references, accounts int
		err = store.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM subscription_nodes WHERE server_pub_key=?`, publicKey).Scan(&references)
		if err == nil && input.ID == "default" {
			err = store.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&accounts)
		}
		if err != nil || references > 0 || accounts > 0 {
			http.Error(w, "inbound is referenced by existing accounts or subscriptions", http.StatusConflict)
			return
		}
	}
	var record inboundRecord
	var revision int64
	if r.Method == http.MethodDelete {
		revision, err = store.deleteInbound(r.Context(), input.ID, input.Revision)
	} else {
		record, revision, err = store.putInbound(r.Context(), *input.Settings, input.Revision, r.Method == http.MethodPost)
	}
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errInboundNotFound) {
			status = http.StatusNotFound
		}
		if errors.Is(err, errInboundConflict) || errors.Is(err, errInboundExists) || errors.Is(err, errInboundReferenced) {
			status = http.StatusConflict
		}
		http.Error(w, "inbound could not be saved; reload and check settings", status)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"revision": revision, "record": record, "applied": false})
}
