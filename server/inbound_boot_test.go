package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A fresh process exercises the actual entry point and writer lock. It never
// starts a second core against a database still owned by the parent test.
func TestNativeInboundCoreChild(t *testing.T) {
	path := os.Getenv("ATLANT_NATIVE_BOOT_CONFIG")
	if path == "" {
		t.Skip("isolated child process only")
	}
	settings, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Keep donor-certificate generation local; do not fetch an Internet donor
	// just to inspect listener startup and the authenticated management endpoint.
	once := &sync.Once{}
	once.Do(func() {})
	sniInitOnceMap.Store(settings.SNI, once)
	donorCertChains[settings.SNI] = [][]byte{generateValidASN1Cert(settings.SNI)}
	os.Args = []string{"atlant-server", "-c", path}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	t.Fatal("server main returned before the parent stopped it")
}

func TestNativeCoreBootUsesCatalogInsteadOfLegacyListener(t *testing.T) {
	for _, scenario := range []struct{ empty, pending bool }{{false, false}, {true, false}, {false, true}} {
		empty, pending := scenario.empty, scenario.pending
		t.Run(fmt.Sprintf("empty=%v/pending=%v", empty, pending), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			store, path := inboundStoreFixture(t)
			if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
				t.Fatal(err)
			}
			var record inboundRecord
			if !empty {
				spec := inboundFixture("default", freeInboundAddress(t))
				spec.SNI, spec.Transports = "localhost.", []string{"tcp"}
				var err error
				record, _, err = store.putInbound(ctx, spec, 1, true)
				if err != nil {
					t.Fatal(err)
				}
				if pending {
					applied, err := store.readInboundCatalog(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if err := store.saveAppliedInboundCatalog(ctx, applied); err != nil {
						t.Fatal(err)
					}
					candidate := record.Settings
					candidate.Listen = freeInboundAddress(t)
					if _, _, err := store.putInbound(ctx, candidate, applied.Revision, false); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			trap, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer trap.Close()
			settings := DefaultConfig()
			settings.UsersFile, settings.WireVersion, settings.LegacyWire = path, 7, false
			settings.ServerAddr, settings.SNI = trap.Addr().String(), "localhost."
			settings.ServerKeyFile = filepath.Join(filepath.Dir(path), "not-created", "legacy.key")
			settings.APIAddr = freeInboundAddress(t)
			settings.APISecret = "local-test-administration-credential-only"
			settings.LogLevel = "error"
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(filepath.Dir(path), "core.json")
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeInboundCoreChild$", "-test.timeout=12s")
			cmd.Env = append(os.Environ(), "ATLANT_NATIVE_BOOT_CONFIG="+configPath)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var processErr error
			go func() { processErr = cmd.Wait(); close(done) }()
			t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
			client := &http.Client{Timeout: 300 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			var response struct {
				Initialized bool            `json:"initialized"`
				Revision    int64           `json:"revision"`
				Applied     int64           `json:"applied_revision"`
				Running     bool            `json:"running"`
				Inbounds    []inboundRecord `json:"inbounds"`
			}
			ticker := time.NewTicker(30 * time.Millisecond)
			defer ticker.Stop()
			ready := false
			for !ready {
				request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+settings.APIAddr+"/api/inbounds", nil)
				request.Header.Set("X-API-Key", settings.APISecret)
				res, err := client.Do(request)
				if err == nil {
					body, readErr := io.ReadAll(io.LimitReader(res.Body, 65536))
					res.Body.Close()
					if res.StatusCode == 200 && readErr == nil && json.Unmarshal(body, &response) == nil {
						ready = true
						break
					}
				}
				select {
				case <-done:
					t.Fatalf("core exited during startup: %v\n%s", processErr, output.String())
				case <-ctx.Done():
					t.Fatal("core management API did not become ready")
				case <-ticker.C:
				}
			}
			if !response.Initialized || !response.Running || (!pending && response.Applied != response.Revision) || (pending && (response.Applied != 2 || response.Revision != 3)) {
				t.Fatal("core did not apply stored catalog")
			}
			if !empty {
				if len(response.Inbounds) != 1 || response.Inbounds[0].PublicKey != record.PublicKey {
					t.Fatal("core boot changed stored key")
				}
				conn, err := net.DialTimeout("tcp", record.Settings.Listen, time.Second)
				if err != nil {
					t.Fatal("stored TCP listener not running", err)
				}
				conn.Close()
			} else if len(response.Inbounds) != 0 {
				t.Fatal("empty catalog resurrected old listener")
			}
			res, err := client.Get("http://" + settings.APIAddr + "/api/inbounds")
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("catalog endpoint bypasses API authentication")
			}
			res, err = client.Post("http://"+settings.APIAddr+"/api/inbounds/apply", "application/json", bytes.NewBufferString(`{"revision":1}`))
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("apply bypasses API authentication")
			}
			if !empty && !pending {
				requestJSON := func(method, path string, payload any) []byte {
					body, _ := json.Marshal(payload)
					req, _ := http.NewRequestWithContext(ctx, method, "http://"+settings.APIAddr+path, bytes.NewReader(body))
					req.Header.Set("X-API-Key", settings.APISecret)
					req.Header.Set("Content-Type", "application/json")
					result, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					data, err := io.ReadAll(result.Body)
					result.Body.Close()
					if err != nil || result.StatusCode != 200 {
						t.Fatal("native operation failed", result.StatusCode, err, string(data))
					}
					return data
				}
				candidate := record.Settings
				candidate.Name = "Edited through real API"
				requestJSON(http.MethodPut, "/api/inbounds", map[string]any{"revision": response.Revision, "settings": candidate})
				expected := response.Revision + 1
				requestJSON(http.MethodPost, "/api/inbounds/apply", map[string]any{"revision": expected})
				data := requestJSON(http.MethodGet, "/api/inbounds", nil)
				if json.Unmarshal(data, &response) != nil || response.Revision != expected || response.Applied != expected || !response.Running {
					t.Fatal("main did not survive planned listener replacement")
				}
				assertInboundListening(t, record.Settings.Listen)
			}
			if _, err := os.Stat(settings.ServerKeyFile); !os.IsNotExist(err) {
				t.Fatal("core depended on old key file", err)
			}
		})
	}
}
