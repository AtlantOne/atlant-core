package main

import (
	"encoding/json"
	"net/http"
	"os"
)

func handleAPISubscriptionService(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		configMu.RLock()
		c := cfg.Subscriptions
		configMu.RUnlock()
		json.NewEncoder(w).Encode(struct {
			SubscriptionConfig
			Status map[string]any `json:"status"`
		}{c, subscriptionCertificateStatus()})
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", 405)
		return
	}
	var c SubscriptionConfig
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		http.Error(w, "invalid subscription settings", 400)
		return
	}
	if err := validateSubscriptionConfig(c, cfg.ServerAddr); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	configMu.Lock()
	defer configMu.Unlock()
	if cfg.ConfigFile == "" {
		http.Error(w, "start with a configuration file to persist subscription settings", 409)
		return
	}
	data, err := os.ReadFile(cfg.ConfigFile)
	if err != nil {
		http.Error(w, "cannot read configuration", 500)
		return
	}
	var existing map[string]json.RawMessage
	if json.Unmarshal(data, &existing) != nil || existing == nil {
		http.Error(w, "invalid existing configuration; retained", 500)
		return
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		http.Error(w, "serialization failed", 500)
		return
	}
	existing["subscriptions"] = encoded
	data, err = json.MarshalIndent(existing, "", "  ")
	if err != nil || writePrivateAtomic(cfg.ConfigFile, data) != nil {
		http.Error(w, "configuration not committed", 500)
		return
	}
	cfg.Subscriptions = c
	json.NewEncoder(w).Encode(map[string]any{"success": true, "restart_required": true, "config": c})
}
