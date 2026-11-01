package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cliTestLink() string {
	return "atlant://192.0.2.12:1026?wire_version=7&sni=www.example.com&user=test&pbk=test-secret&server_pub_key=test-public#Test"
}

func newTestCLI(t *testing.T) *clientCLI {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return &clientCLI{dir: dir, state: cliCatalog{Version: 1, Settings: cliDefaults()}, in: bufio.NewReader(strings.NewReader("")), out: &bytes.Buffer{}}
}

func TestCLIProfileShareRoundtrip(t *testing.T) {
	p, err := cliParseProfile(cliTestLink())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := cliParseProfile(cliShare(p))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Config.PBK != p.Config.PBK || p2.Name != p.Name || p2.Config.User != p.Config.User {
		t.Fatal("share lost profile fields")
	}
	if _, err := cliParseProfile(strings.Replace(cliTestLink(), "wire_version=7", "wire_version=4", 1)); err == nil {
		t.Fatal("legacy profile accepted")
	}
}

func TestCLIPrivatePersistenceAndFirstSelection(t *testing.T) {
	c := newTestCLI(t)
	p, _ := cliParseProfile(cliTestLink())
	c.addProfile(p)
	if c.state.Active != p.ID {
		t.Fatal("first profile not selected")
	}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(c.dir, "catalog.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("state exposed")
	}
	if err := c.locked(func() error {
		if c.state.Active != p.ID {
			t.Fatal("selection not persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRejectsSymlinkAndCorruptCatalog(t *testing.T) {
	c := newTestCLI(t)
	outside := filepath.Join(t.TempDir(), "data")
	os.WriteFile(outside, []byte("private"), 0600)
	if err := os.Symlink(outside, filepath.Join(c.dir, "catalog.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.read("catalog.json"); err == nil {
		t.Fatal("symlink followed")
	}
	os.Remove(filepath.Join(c.dir, "catalog.json"))
	os.WriteFile(filepath.Join(c.dir, "catalog.json"), []byte("bad json"), 0600)
	if err := c.locked(func() error { return c.save() }); err == nil {
		t.Fatal("corrupt state overwritten")
	}
	data, _ := os.ReadFile(filepath.Join(c.dir, "catalog.json"))
	if string(data) != "bad json" {
		t.Fatal("original lost")
	}
}

func TestCLISubscriptionRotationKeepsOrderNameAndSelection(t *testing.T) {
	c := newTestCLI(t)
	p, _ := cliParseProfile(cliTestLink())
	s := cliSubscription{ID: "a", Name: "My name", URL: "https://example.com/a"}
	c.replaceSubscription(s, []cliProfile{p})
	selected := c.state.Active
	c.replaceSubscription(cliSubscription{ID: "b", Name: "Second"}, []cliProfile{p})
	p.Config.PBK = "rotated"
	s.Name = "provider rename"
	c.replaceSubscription(s, []cliProfile{p})
	if c.state.Subscriptions[0].ID != "a" || c.state.Subscriptions[0].Name != "My name" || c.state.Active != selected || c.state.Profiles[0].Config.PBK != "rotated" {
		t.Fatal("refresh changed grouping, name, selection or retained stale key")
	}
}

func TestCLIFetchPreservesDataOnHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Subscription-Userinfo", "upload=3; download=7; total=100; expire=2000000000")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(cliTestLink()))))
	}))
	defer server.Close()
	s, p, err := cliFetchSubscription(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 1 || s.Total != 100 || s.Upload != 3 || s.Download != 7 {
		t.Fatal("metadata or base64 decode lost")
	}
	c := newTestCLI(t)
	c.replaceSubscription(s, p)
	before, _ := json.Marshal(c.state)
	_, _, err = cliFetchSubscription(server.URL + "/fail")
	if err == nil {
		t.Fatal("503 accepted")
	}
	after, _ := json.Marshal(c.state)
	if !bytes.Equal(before, after) {
		t.Fatal("failed update mutated state")
	}
}

func TestCLISubscriptionURLPolicy(t *testing.T) {
	for _, raw := range []string{"http://example.com/sub", "file:///tmp/key", "https://u:p@example.com/sub", "https://example.com/sub#fragment"} {
		if cliSubscriptionURL(raw) == nil {
			t.Fatalf("unsafe URL accepted: %s", raw)
		}
	}
	if cliSubscriptionURL("https://example.com/sub") != nil {
		t.Fatal("HTTPS rejected")
	}
}

func TestCLISettingsValidationAndSecretIsolation(t *testing.T) {
	c := newTestCLI(t)
	for _, args := range [][]string{{"set", "local", "0.0.0.0:1080"}, {"set", "mtu", "1"}, {"set", "fingerprint", "chrome_120"}, {"set", "pbk", "secret"}, {"set", "tun", "nonsense"}} {
		if c.settings(args) == nil {
			t.Fatalf("invalid setting accepted: %v", args)
		}
	}
	if err := c.settings([]string{"set", "fingerprint", "chrome_144"}); err != nil {
		t.Fatal(err)
	}
	if c.state.Settings.PBK != "" {
		t.Fatal("profile secret in global settings")
	}
}

func TestCLIStaleProcessNeverSignaled(t *testing.T) {
	c := newTestCLI(t)
	exe, _ := os.Executable()
	c.write("process.json", cliProcess{PID: os.Getpid(), Start: "wrong", Executable: exe})
	if c.alive() {
		t.Fatal("stale identity accepted")
	}
	if err := c.disconnect(); err != nil {
		t.Fatal(err)
	}
}

func TestCLIHelpDoesNotCreateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	var out bytes.Buffer
	if err := runClientCLI([]string{"--state", path, "help"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("help created state")
	}
	if !strings.Contains(out.String(), "subscriptions") {
		t.Fatal("incomplete help")
	}
}
