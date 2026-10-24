package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestConfigUpdatesSynchronizeWithRuntimeReaders(t *testing.T) {
	isolateUsers(t)
	cfg.Bandwidth.UpMbps = 100
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for i := 0; i < 500; i++ {
			_ = cfg.GetSNI()
			_ = cfg.GetAdvertiseAddr()
			_ = cfg.GetUpMbps()
			_ = cfg.GetDownMbps()
			_ = generateAtlantLink("alice", "test-key")
		}
	}()
	for i := 0; i < 30; i++ {
		response := httptest.NewRecorder()
		handleAPIUpdateConfig(response, httptest.NewRequest(http.MethodPost, "/api/config/update", strings.NewReader(`{"sni":"example.com","advertise_addr":"example.com:443","up_mbps":0,"down_mbps":10}`)))
		if response.Code != http.StatusOK {
			t.Fatal(response.Body.String())
		}
	}
	readers.Wait()
	if cfg.GetUpMbps() != 0 {
		t.Fatal("explicit unlimited setting was ignored by nested bandwidth config")
	}
}

func TestConfigurationMutationRequiresWriteMethod(t *testing.T) {
	response := httptest.NewRecorder()
	handleAPIUpdateConfig(response, httptest.NewRequest(http.MethodGet, "/api/config/update", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatal("GET can modify configuration")
	}
}

func TestConfigRejectsInvalidEndpointAndBlankSNI(t *testing.T) {
	for _, body := range []string{`{"sni":" "}`, `{"advertise_addr":"host:65536"}`} {
		response := httptest.NewRecorder()
		handleAPIUpdateConfig(response, httptest.NewRequest(http.MethodPost, "/api/config/update", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid config accepted: %s", body)
		}
	}
}
