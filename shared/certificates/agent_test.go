package certificates

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/gofrs/flock"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentChallengeListenerBehindProxy(t *testing.T) {
	for _, address := range []string{":80", "127.0.0.1:18081", "[::1]:18081"} {
		config := AgentConfig{StateDir: t.TempDir(), ChallengeListen: address, Jobs: []Job{}}
		if err := config.Validate(); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{":18081", "0.0.0.0:18081", "192.168.1.2:18081", "localhost:18081", "127.0.0.1:0", "127.0.0.1:65536"} {
		config := AgentConfig{StateDir: t.TempDir(), ChallengeListen: address, Jobs: []Job{}}
		if config.Validate() == nil {
			t.Errorf("unsafe listener accepted: %s", address)
		}
	}
}

func TestChallengeBrokerHostTokenAndExpiryIsolation(t *testing.T) {
	dir := t.TempDir()
	remove, err := publishChallenge(dir, "one.example.test", "one-token", "one-response")
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	other, err := publishChallenge(dir, "two.example.test", "two-token", "two-response")
	if err != nil {
		t.Fatal(err)
	}
	defer other()
	handler := ChallengeBroker(dir)
	for _, test := range []struct {
		method, host, path string
		code               int
	}{{"GET", "one.example.test", "/.well-known/acme-challenge/one-token", 200}, {"GET", "two.example.test", "/.well-known/acme-challenge/one-token", 404}, {"GET", "one.example.test", "/.well-known/acme-challenge/two-token", 404}, {"POST", "one.example.test", "/.well-known/acme-challenge/one-token", 404}, {"GET", "one.example.test", "/.well-known/acme-challenge/one-token?x=1", 404}, {"GET", "one.example.test", "/status.json", 404}} {
		r := httptest.NewRequest(test.method, "http://"+test.host+test.path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.code {
			t.Fatal(test, w.Code)
		}
	}
	data, _ := json.Marshal(challengeFile{Host: "one.example.test", Response: "expired", Expires: time.Now().Add(-time.Second).Unix()})
	if err := writePrivateAtomic(challengePath(dir, "one.example.test", "one-token"), data); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://one.example.test/.well-known/acme-challenge/one-token", nil))
	if w.Code != 404 {
		t.Fatal("expired challenge served")
	}
	remove()
	if _, err := os.Stat(challengePath(dir, "one.example.test", "one-token")); !os.IsNotExist(err) {
		t.Fatal("challenge cleanup failed")
	}
}

func cachedAgent(t *testing.T) *Agent {
	t.Helper()
	dir := t.TempDir()
	cache := filepath.Join(dir, "panel")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	cert, key := testSubscriptionCertificate(t, "198.51.100.20", 160*time.Hour)
	context := New(Config{Mode: "acme-ip", Host: "198.51.100.20"}).cacheContext()
	bundle := append(append(cert, key...), pem.EncodeToMemory(&pem.Block{Type: "ATLANT CERTIFICATE CONTEXT", Bytes: context})...)
	if err := writePrivateAtomic(filepath.Join(cache, "subscription.pem"), bundle); err != nil {
		t.Fatal(err)
	}
	agent, err := NewAgent(AgentConfig{StateDir: filepath.Join(dir, "agent"), ChallengeListen: ":80", Jobs: []Job{{ID: "panel", TLS: Config{Mode: "acme-ip", Host: "198.51.100.20", CacheDir: cache, AcceptTerms: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	agent.listener = func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	return agent
}

func TestAgentRestartUsesCacheAndStopsCleanly(t *testing.T) {
	agent := cachedAgent(t)
	for iteration := 0; iteration < 2; iteration++ {
		agent.mu.Lock()
		agent.status = map[string]map[string]any{}
		agent.mu.Unlock()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- agent.Run(ctx) }()
		deadline := time.After(3 * time.Second)
		for {
			agent.mu.Lock()
			status := agent.status["panel"]
			valid := status != nil && status["not_after"] != nil
			agent.mu.Unlock()
			if valid {
				break
			}
			select {
			case err := <-done:
				cancel()
				t.Fatal("agent exited early", err)
			case <-deadline:
				cancel()
				t.Fatal("agent did not publish cache status")
			case <-time.After(10 * time.Millisecond):
			}
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("agent did not shut down")
		}
		data, err := os.ReadFile(filepath.Join(agent.config.StateDir, "status.json"))
		if err != nil || strings.Contains(string(data), "PRIVATE KEY") {
			t.Fatal("invalid public status", err)
		}
	}
}

func TestAgentPortConflictDoesNotReplaceOrStopAnotherService(t *testing.T) {
	agent := cachedAgent(t)
	agent.listener = func(string, string) (net.Listener, error) { return nil, errors.New("address in use") }
	if err := agent.Run(context.Background()); err == nil {
		t.Fatal("port conflict ignored")
	}
	data, err := os.ReadFile(filepath.Join(agent.config.StateDir, "status.json"))
	if err != nil || !strings.Contains(string(data), "no existing service was changed") {
		t.Fatal("missing actionable port conflict", err)
	}
}

func TestAgentCannotSilentlyLoseStatusWrites(t *testing.T) {
	agent := cachedAgent(t)
	if err := os.MkdirAll(filepath.Join(agent.config.StateDir, "status.json"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := agent.Run(ctx); err == nil {
		t.Fatal("status persistence failure left agent reporting success")
	}
}

func TestCertificateCacheHasSingleIssuer(t *testing.T) {
	options := Config{Mode: "acme-domain", Host: "example.test", CacheDir: t.TempDir(), AcceptTerms: true}
	lock := flock.New(filepath.Join(options.CacheDir, ".issuer.lock"), flock.SetPermissions(0600))
	if ok, err := lock.TryLock(); err != nil || !ok {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(options).Issue(ctx); err == nil || !strings.Contains(err.Error(), "another certificate issuer") {
		t.Fatal("parallel issuer entered shared cache", err)
	}
}

func TestEnsureRechecksCacheInsideIssuerLockAndDoesNotIssueAgain(t *testing.T) {
	agent := cachedAgent(t)
	options := agent.config.Jobs[0].TLS
	options.RequireContext = true
	manager := New(options)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Ensure(ctx); err != nil {
		t.Fatal("fresh shared cache caused another CA request", err)
	}
	if manager.certificate == nil || !manager.lastAttempt.IsZero() {
		t.Fatal("cache reuse reported a new CA issuance")
	}
}

func TestHTTPConnectionLimitReleasesExactlyOnce(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	connection := &limitedConnection{Conn: left, slots: slots}
	_ = connection.Close()
	_ = connection.Close()
	if len(slots) != 0 {
		t.Fatal("closed HTTP connection retained its slot")
	}
}

func TestAgentRejectsInvalidModesTermsAndDuplicateIdentities(t *testing.T) {
	agent := cachedAgent(t)
	original := agent.config
	for _, edit := range []func(*AgentConfig){func(c *AgentConfig) { c.Jobs[0].TLS.AcceptTerms = false }, func(c *AgentConfig) { c.ChallengeListen = ":443" }, func(c *AgentConfig) { c.Jobs[0].ID = "agent" }, func(c *AgentConfig) { c.Jobs[0].TLS.Host = "bad..example.com"; c.Jobs[0].TLS.Mode = "acme-domain" }, func(c *AgentConfig) { c.Jobs = append(c.Jobs, c.Jobs[0]) }} {
		copy := original
		copy.Jobs = append([]Job(nil), original.Jobs...)
		edit(&copy)
		if _, err := NewAgent(copy); err == nil {
			t.Fatal("invalid agent configuration accepted")
		}
	}
}
