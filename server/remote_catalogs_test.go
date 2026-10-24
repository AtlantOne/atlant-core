package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func remoteCatalogFixture(t *testing.T) remoteInboundCatalog {
	t.Helper()
	record := inboundRecordFixture(t, "remote", "127.0.0.1:20127")
	return remoteInboundCatalog{PeerID: strings.Repeat("a", 32), publicAppliedCatalog: publicAppliedCatalog{ServerID: strings.Repeat("b", 32), Revision: 2, Inbounds: []inboundRecord{record}}}
}

func TestRemoteCatalogIdentityRevisionAndPersistence(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	ctx := context.Background()
	fixture := remoteCatalogFixture(t)
	if err := storeRemoteCatalog(ctx, store, fixture); err != nil {
		t.Fatal(err)
	}
	if err := storeRemoteCatalog(ctx, store, fixture); err != nil {
		t.Fatal("idempotent sync", err)
	}
	for _, change := range []func(*remoteInboundCatalog){
		func(c *remoteInboundCatalog) { c.Revision-- },
		func(c *remoteInboundCatalog) { c.PeerID = strings.Repeat("c", 32) },
		func(c *remoteInboundCatalog) { c.Inbounds = nil },
		func(c *remoteInboundCatalog) { c.ServerID, _ = localControlServerID(ctx, store.db) },
		func(c *remoteInboundCatalog) { c.ServerID = strings.Repeat("d", 32) },
		func(c *remoteInboundCatalog) { c.ServerID = strings.ToUpper(c.ServerID) },
	} {
		candidate := fixture
		change(&candidate)
		if err := storeRemoteCatalog(ctx, store, candidate); err == nil {
			t.Fatal("conflicting identity/revision accepted", candidate)
		}
	}
	fixture.Revision++
	if err := storeRemoteCatalog(ctx, store, fixture); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIRemoteCatalogs(w, httptest.NewRequest(http.MethodGet, "/api/control/catalogs", nil))
	var items []remoteInboundCatalog
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &items) != nil || len(items) != 1 || items[0].Revision != 3 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "identity") {
		t.Fatal("private identity leaked")
	}
	backup, err := store.inboundMigrationBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := openSQLiteUsers(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var count int
	if err := snapshot.db.QueryRow(`SELECT count(*) FROM remote_inbound_catalogs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("catalog absent from recovery snapshot", count, err)
	}
}

func TestAppliedCatalogEndpointDoesNotPublishPendingSettings(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	ctx := context.Background()
	spec := inboundFixture("first", "127.0.0.1:20128")
	if _, _, err := store.putInbound(ctx, spec, 1, true); err != nil {
		t.Fatal(err)
	}
	applied, err := store.readInboundCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveAppliedInboundCatalog(ctx, applied); err != nil {
		t.Fatal(err)
	}
	spec.SNI = "pending.example.com"
	if _, _, err := store.putInbound(ctx, spec, 2, false); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIAppliedInbounds(w, httptest.NewRequest(http.MethodGet, "/api/inbounds/applied", nil))
	var response publicAppliedCatalog
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Revision != 2 || len(response.Inbounds) != 1 || response.Inbounds[0].Settings.SNI == spec.SNI {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private") {
		t.Fatal("private snapshot exposed")
	}
}

func TestRemoteCatalogAPIRejectsMalformedOrPrivateData(t *testing.T) {
	initializedInboundAPIFixture(t)
	fixture := remoteCatalogFixture(t)
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{string(data) + " {}", strings.Replace(string(data), `"server_pub_key":`, `"private":"secret","server_pub_key":`, 1), strings.Replace(string(data), fixture.Inbounds[0].PublicKey, strings.Repeat("0", 64), 1)} {
		w := httptest.NewRecorder()
		handleAPIRemoteCatalogs(w, httptest.NewRequest(http.MethodPost, "/api/control/catalogs", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	handleAPIRemoteCatalogs(w, httptest.NewRequest(http.MethodPost, "/api/control/catalogs", strings.NewReader(string(data))))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestRemoteCatalogRequiresCompleteRecoveryEvenForLegacyCore(t *testing.T) {
	store := initializedInboundAPIFixture(t)
	if _, err := store.db.Exec(`UPDATE inbound_catalog_meta SET initialized=0,revision=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := storeRemoteCatalog(context.Background(), store, remoteCatalogFixture(t)); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	if w.Code != http.StatusConflict {
		t.Fatal("JSON backup silently omitted remote catalog", w.Code, w.Body.String())
	}
}
