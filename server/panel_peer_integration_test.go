package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The Python panel pair uses real HTTPS and the real SQLite-backed Go API.
// No production database, listener or service configuration is used.
func TestPanelPeerChangesReachNativeCore(t *testing.T) {
	panelSource := os.Getenv("ATLANT_PANEL_SOURCE")
	if panelSource == "" {
		panelSource = filepath.Join("..", "management")
	}
	if _, err := os.Stat(filepath.Join(panelSource, "test_control_peers.py")); os.IsNotExist(err) {
		t.Skip("Set ATLANT_PANEL_SOURCE to the separate panel repository's management directory for cross-component acceptance")
	} else if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("Python is required for cross-component acceptance")
	}
	store := initializedInboundAPIFixture(t)
	catalog, err := store.readInboundCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	previous := activeInboundSet.Load()
	controller, err := startInboundController(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	controller.persist = persistAppliedInboundCatalog
	if err := controller.persist(catalog); err != nil {
		controller.Close()
		t.Fatal(err)
	}
	previousController := activeInboundController.Swap(controller)
	t.Cleanup(func() {
		controller.Close()
		activeInboundController.Store(previousController)
		activeInboundSet.Store(previous)
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/inbounds", handleAPIInbounds)
	mux.HandleFunc("/api/inbounds/applied", handleAPIAppliedInbounds)
	mux.HandleFunc("/api/control/catalogs", handleAPIRemoteCatalogs)
	mux.HandleFunc("/api/inbounds/apply", handleInboundMutation)
	mux.HandleFunc("/api/backup", handleAPIBackup)
	mux.HandleFunc("/api/backup/sqlite", handleAPISQLiteBackup)
	credential := "local-panel-acceptance-only"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), []byte(credential)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer api.Close()
	settings, _ := json.Marshal(map[string]string{"api_url": api.URL, "api_key": credential, "listen": freeInboundAddress(t)})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-m", "unittest", "test_control_peers.PairingCoreTests", "-v")
	cmd.Dir = panelSource
	cmd.Env = append(os.Environ(), "ATLANT_PEER_TEST_CORE="+string(settings))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("panel/core acceptance: %v\n%s", err, output)
	}
	t.Log(string(output))
	final, err := store.readInboundCatalog(context.Background())
	if err != nil || final.Revision != 4 || len(final.Inbounds) != 0 || activeInboundSet.Load().revision != 4 {
		t.Fatalf("unexpected final catalog: %+v / %v", final, err)
	}
}
