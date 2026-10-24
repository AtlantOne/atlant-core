package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboundAPISeparatesSavedAndAppliedStateWithoutPrivateKeys(t *testing.T) {
	isolateUsers(t)
	ctx := context.Background()
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("first", freeInboundAddress(t))
	spec.Transports = []string{"tcp"}
	record, _, err := store.putInbound(ctx, spec, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	running, err := startInboundSet(ctx, catalog)
	if err != nil {
		t.Fatal(err)
	}
	previous := activeInboundSet.Swap(running)
	t.Cleanup(func() { activeInboundSet.Store(previous); running.Close() })
	spec.SNI = "saved-not-applied.example.com"
	if _, _, err := store.putInbound(ctx, spec, 2, false); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIInbounds(w, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	var response struct {
		inboundCatalog
		AppliedRevision int64    `json:"applied_revision"`
		Running         bool     `json:"running"`
		Active          []string `json:"active"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Revision != 3 || response.AppliedRevision != 2 || !response.Running || len(response.Active) != 1 {
		t.Fatal("saved state presented as applied", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "identity") || strings.Contains(w.Body.String(), "private") || response.Inbounds[0].PublicKey != record.PublicKey || response.Inbounds[0].Settings.SNI != spec.SNI {
		t.Fatal("public inbound response invalid")
	}
	w = httptest.NewRecorder()
	oldSNI := cfg.GetSNI()
	handleAPIUpdateConfig(w, httptest.NewRequest(http.MethodPost, "/api/config/update", strings.NewReader(`{"sni":"ignored.example.com"}`)))
	if w.Code != http.StatusConflict || cfg.GetSNI() != oldSNI {
		t.Fatal("global settings bypassed inbound ownership")
	}
	w = httptest.NewRecorder()
	handleAPIInbounds(w, httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatal("write route accepted an incomplete mutation")
	}
	running.Close()
	w = httptest.NewRecorder()
	handleAPIInbounds(w, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Running || len(response.Active) != 0 {
		t.Fatal("stopped runtime advertised as running", err)
	}
}

func TestInitializedCatalogIdentityDoesNotDependOnOldKeyFile(t *testing.T) {
	isolateUsers(t)
	previousKey, previousPublic := serverStaticECDH, serverStaticPubHexStr
	t.Cleanup(func() { serverStaticECDH, serverStaticPubHexStr = previousKey, previousPublic })
	cfg.WireVersion, cfg.LegacyWire = 7, false
	cfg.ServerKeyFile = filepath.Join(t.TempDir(), "missing-parent", "legacy.key")
	ctx := context.Background()
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("default", freeInboundAddress(t))
	record, _, err := store.putInbound(ctx, spec, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := initServerIdentityForCatalog(cfg); err != nil || getServerStaticPubHex() != record.PublicKey {
		t.Fatal("stored identity not loaded", err)
	}
	if _, err := os.Stat(cfg.ServerKeyFile); !os.IsNotExist(err) {
		t.Fatal("legacy key file was created or read", err)
	}
	cfg.WireVersion = 6
	if err := initServerIdentityForCatalog(cfg); err == nil {
		t.Fatal("initialized catalog allowed old wire fallback")
	}
	cfg.WireVersion = 7
	if _, err := store.deleteInbound(ctx, "default", 2); err != nil {
		t.Fatal(err)
	}
	if err := initServerIdentityForCatalog(cfg); err != nil || serverStaticECDH != nil || getServerStaticPubHex() != "" {
		t.Fatal("empty catalog resurrected legacy identity", err)
	}
	catalog, err := prepareNativeInboundCatalog(ctx, cfg)
	if err != nil || catalog == nil || len(catalog.Inbounds) != 0 {
		t.Fatal("empty catalog switched to legacy listener", err)
	}
}

func TestNativePreparationMigratesOnlyOnceAndRejectsDowngrade(t *testing.T) {
	isolateUsers(t)
	previous := serverStaticECDH
	t.Cleanup(func() { serverStaticECDH = previous })
	serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
	cfg.WireVersion, cfg.LegacyWire = 7, false
	catalog, err := prepareNativeInboundCatalog(context.Background(), cfg)
	if err != nil || catalog == nil || catalog.Revision != 1 || len(catalog.Inbounds) != 1 {
		t.Fatal("first native preparation failed", err)
	}
	key := catalog.Inbounds[0].PublicKey
	cfg.SNI = "changed-but-not-authoritative.example.com"
	serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
	catalog, err = prepareNativeInboundCatalog(context.Background(), cfg)
	if err != nil || catalog.Inbounds[0].PublicKey != key || catalog.Inbounds[0].Settings.SNI == cfg.SNI {
		t.Fatal("old config overwrote initialized catalog", err)
	}
	cfg.WireVersion = 6
	if _, err := prepareNativeInboundCatalog(context.Background(), cfg); err == nil {
		t.Fatal("native catalog silently switched to legacy mode")
	}
}
