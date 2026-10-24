package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestManagementPanelSecurityHeadersAndPublicServiceSeparation(t *testing.T) {
	w := httptest.NewRecorder()
	managementPanelHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost/panel/", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("unsafe panel headers", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Сервер под контролем") {
		t.Fatal("embedded panel missing")
	}
	public := http.NewServeMux()
	public.HandleFunc("/sub/", publicSubscriptionHandler)
	w = httptest.NewRecorder()
	public.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://localhost/panel/", nil))
	if w.Code != 404 {
		t.Fatal("panel exposed on subscription listener")
	}
}

// Read-only UI fixtures, no live server, real user, secret, VPN or certificate.
func TestManagementPanelPreview(t *testing.T) {
	if os.Getenv("ATLANT_PANEL_PREVIEW") != "1" {
		t.Skip("explicit local visual preview only")
	}
	mux := http.NewServeMux()
	mux.Handle("/panel/", managementPanelHandler())
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"users": []map[string]any{{"name": "preview", "enabled": true, "up_bytes": 1024, "down_bytes": 5000000000, "total_limit": 10000000000}}})
	})
	mux.HandleFunc("/api/subscriptions", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]SubscriptionRecord{{ID: strings.Repeat("a", 32), User: "preview", Title: "Личный VPN · Европа", Enabled: true, UpdateHours: 1, Nodes: []SubscriptionNode{{Name: "Германия · QUIC", Server: "198.51.100.20:443", SNI: "example.com", Transport: "quic", WireVersion: 3}}}})
	})
	mux.HandleFunc("/api/subscription-service", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(SubscriptionConfig{Listen: ":8443", TLS: SubscriptionTLSConfig{Mode: "manual"}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	fmt.Println("LOCAL_READ_ONLY_PREVIEW " + server.URL + "/panel/")
	timer := time.NewTimer(8 * time.Minute)
	defer timer.Stop()
	<-timer.C
}
