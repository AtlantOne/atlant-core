package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func inboundRequest(t *testing.T, method, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIInbounds(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
	return w
}

func initializedInboundAPIFixture(t *testing.T) *sqliteUserStore {
	t.Helper()
	isolateUsers(t)
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(context.Background(), nil, nil); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestInboundMutationAPIBacksUpEditsWithoutApplyingAndChecksRevision(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	spec := inboundFixture("new", freeInboundAddress(t))
	spec.Enabled = false
	w := inboundRequest(t, http.MethodPost, "/api/inbounds", map[string]any{"revision": 1, "settings": spec})
	var created struct {
		Revision int64         `json:"revision"`
		Record   inboundRecord `json:"record"`
		Applied  bool          `json:"applied"`
		BackupID string        `json:"backup_id"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.Revision != 2 || created.Applied || created.BackupID != "" {
		t.Fatal(w.Code, w.Body.String())
	}
	if copies, _ := filepath.Glob(filepath.Join(filepath.Dir(store.path), ".atlant-pre-inbounds-*")); len(copies) != 0 {
		t.Fatal("inbound mutation created an automatic backup")
	}
	if w := inboundRequest(t, http.MethodPut, "/api/inbounds", map[string]any{"revision": 1, "settings": spec}); w.Code != 409 {
		t.Fatal("stale form accepted", w.Code)
	}
	spec.SNI = "edited.example.com"
	w = inboundRequest(t, http.MethodPut, "/api/inbounds", map[string]any{"revision": 2, "settings": spec})
	var edited struct {
		Record inboundRecord `json:"record"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &edited) != nil || edited.Record.PublicKey != created.Record.PublicKey {
		t.Fatal("edit changed identity", w.Body.String())
	}
	if w := inboundRequest(t, http.MethodDelete, "/api/inbounds", map[string]any{"revision": 3, "id": "new"}); w.Code != 200 {
		t.Fatal("delete failed", w.Code, w.Body.String())
	}
	catalog, err := store.readInboundCatalog(context.Background())
	if err != nil || catalog.Revision != 4 || len(catalog.Inbounds) != 0 {
		t.Fatal("deletion not persisted", err)
	}
}

func TestInboundMutationBackupFailureAndStrictJSONLeaveCatalogUntouched(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	spec := inboundFixture("new", freeInboundAddress(t))
	for _, body := range []string{`{"revision":1,"settings":{},"private_key":"no"}`, `{"revision":1} {}`, `{"revision":1,"id":"x","settings":{}}`} {
		w := httptest.NewRecorder()
		handleAPIInbounds(w, httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal("invalid JSON accepted", w.Code)
		}
	}
	path := store.path
	store.path = filepath.Join(t.TempDir(), "missing", "users.db")
	w := inboundRequest(t, http.MethodPost, "/api/inbounds", map[string]any{"revision": 1, "settings": spec})
	store.path = path
	if w.Code != 503 {
		t.Fatal("backup failure ignored", w.Code, w.Body.String())
	}
	catalog, err := store.readInboundCatalog(context.Background())
	if err != nil || catalog.Revision != 1 || len(catalog.Inbounds) != 0 {
		t.Fatal("failed operation mutated catalog", err)
	}
}

func TestInboundApplyAPIReportsRollbackAndSavedAppliedDifference(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	spec := inboundFixture("first", freeInboundAddress(t))
	spec.Transports = []string{"tcp"}
	if _, _, err := store.putInbound(context.Background(), spec, 1, true); err != nil {
		t.Fatal(err)
	}
	catalog, _ := store.readInboundCatalog(context.Background())
	previous := activeInboundSet.Load()
	c, err := startInboundController(context.Background(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	previousController := activeInboundController.Swap(c)
	t.Cleanup(func() { c.Close(); activeInboundController.Store(previousController); activeInboundSet.Store(previous) })
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	spec.Listen = occupied.Addr().String()
	if _, _, err := store.putInbound(context.Background(), spec, 2, false); err != nil {
		t.Fatal(err)
	}
	w := inboundRequest(t, http.MethodPost, "/api/inbounds/apply", map[string]any{"revision": 3})
	var failed struct {
		Restored bool `json:"runtime_restored"`
	}
	if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &failed) != nil || !failed.Restored || activeInboundSet.Load().revision != 2 {
		t.Fatal("rollback misreported", w.Code, w.Body.String())
	}
	assertInboundListening(t, catalog.Inbounds[0].Settings.Listen)
	occupied.Close()
	w = inboundRequest(t, http.MethodPost, "/api/inbounds/apply", map[string]any{"revision": 3})
	if w.Code != 200 || activeInboundSet.Load().revision != 3 {
		t.Fatal("retry failed", w.Code, w.Body.String())
	}
	assertInboundListening(t, spec.Listen)
	w = inboundRequest(t, http.MethodPost, "/api/inbounds/apply", map[string]any{"revision": 2})
	if w.Code != 409 {
		t.Fatal("stale apply accepted", w.Code)
	}
}

func TestInboundControllerTransitionStillRejectsGlobalSettingsWrites(t *testing.T) {
	isolateUsers(t)
	previousSet := activeInboundSet.Swap(nil)
	previousController := activeInboundController.Swap(&inboundController{})
	defer func() { activeInboundSet.Store(previousSet); activeInboundController.Store(previousController) }()
	w := httptest.NewRecorder()
	handleAPIUpdateConfig(w, httptest.NewRequest(http.MethodPost, "/api/config/update", strings.NewReader(`{"sni":"must-not-apply.example.com"}`)))
	if w.Code != http.StatusConflict {
		t.Fatal("runtime transition allowed global settings bypass", w.Code)
	}
}
