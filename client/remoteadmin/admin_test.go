package remoteadmin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLatestPublishedReleaseIsPinnedInsteadOfMain(t *testing.T) {
	old := githubClient
	defer func() { githubClient = old }()
	for _, preview := range []bool{false, true} {
		t.Run(fmt.Sprint(preview), func(t *testing.T) {
			paths := []string{}
			githubClient = &http.Client{Transport: releaseTransport(func(r *http.Request) (*http.Response, error) {
				paths = append(paths, r.URL.Path)
				status := 200
				body := ""
				switch {
				case strings.HasSuffix(r.URL.Path, "/releases/latest"):
					if preview {
						status = 404
						body = `{}`
					} else {
						body = `{"tag_name":"v1.2.3","draft":false}`
					}
				case strings.HasSuffix(r.URL.Path, "/releases"):
					body = `[{"tag_name":"v1.2.4-preview.1","draft":false}]`
				case strings.Contains(r.URL.Path, "/git/ref/tags/"):
					body = `{"object":{"type":"tag","sha":"` + strings.Repeat("a", 40) + `"}}`
				case strings.Contains(r.URL.Path, "/git/tags/"):
					body = `{"object":{"type":"commit","sha":"` + strings.Repeat("b", 40) + `"}}`
				default:
					t.Fatalf("unexpected source endpoint: %s", r.URL.Path)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			sha, err := revision(context.Background(), "core")
			if err != nil || sha != strings.Repeat("b", 40) {
				t.Fatal("release resolution failed", sha, err)
			}
			for _, path := range paths {
				if strings.Contains(path, "heads/main") {
					t.Fatal("unreleased main selected")
				}
			}
		})
	}
}

func TestPublishedReleaseLookupLive(t *testing.T) {
	if os.Getenv("ATLANT_LIVE_RELEASE_LOOKUP") != "1" {
		t.Skip("explicit network integration check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, repo := range []string{"core", "panel"} {
		sha, err := revision(ctx, repo)
		if err != nil {
			t.Fatal(repo, err)
		}
		t.Log(repo, "published release commit", sha)
	}
}

func TestUpdateProgressAndDiagnosticsAreBounded(t *testing.T) {
	j := &job{}
	progress := &installProgress{job: j}
	_, _ = progress.Write([]byte("Updating exis"))
	_, _ = progress.Write([]byte("ting Docker installation\n"))
	if j.state.Phase != "updating" {
		t.Fatal("update stage was not surfaced")
	}
	var diagnostic installDiagnostic
	data := []byte(strings.Repeat("x", 20000))
	n, err := diagnostic.Write(data)
	if err != nil || n != len(data) || len(diagnostic.data) != 1024 {
		t.Fatal("unbounded install diagnostic")
	}
}

func TestProbeDoesNotAuthenticate(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authenticated := make(chan struct{}, 1)
	config := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { authenticated <- struct{}{}; return nil, nil }}
	config.AddHostKey(signer)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		ssh.NewServerConn(conn, config)
	}()
	address := listener.Addr().(*net.TCPAddr)
	fingerprint, err := Probe("127.0.0.1", address.Port)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("wrong fingerprint")
	}
	select {
	case <-authenticated:
		t.Fatal("probe attempted password authentication")
	default:
	}
}

func TestManagementPanelUsesPinnedSSHAndPrivateProxy(t *testing.T) {
	testManagementPanel(t, false)
}

func TestStoppedContainerDoesNotTriggerPanelLogin(t *testing.T) {
	testManagementPanel(t, true)
}

func testManagementPanel(t *testing.T, stopped bool) {
	entry := "/0123456789abcdef0123456789abcdef/"
	var generation atomic.Int32
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == entry+"control/login" {
			var credentials map[string]string
			_ = json.NewDecoder(r.Body).Decode(&credentials)
			if credentials["password"] != "test-panel-secret" {
				http.Error(w, "unauthorized", 401)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "panel-session", Value: fmt.Sprint(generation.Add(1)), Path: entry})
			fmt.Fprint(w, `{"csrf":"test-csrf"}`)
			return
		}
		cookie, err := r.Cookie("panel-session")
		if err != nil || cookie.Value != fmt.Sprint(generation.Load()) {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.URL.Path == entry+"control/prepare" {
			if r.Header.Get("X-CSRF-Token") != "test-csrf" {
				t.Error("missing forwarded CSRF")
			}
			fmt.Fprint(w, `{"result":{"online":3}}`)
			return
		}
		fmt.Fprint(w, `{"managed":true,"csrf":"test-csrf"}`)
	}))
	defer panel.Close()
	backend := strings.TrimPrefix(panel.URL, "http://")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if string(password) != "test-ssh-secret" {
			return nil, fmt.Errorf("unauthorized")
		}
		return nil, nil
	}}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			conn.Close()
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				continue
			}
			if incoming.ChannelType() == "session" {
				go func() {
					defer channel.Close()
					for request := range requests {
						if request.Type == "exec" {
							_ = request.Reply(true, nil)
							var command struct{ Command string }
							_ = ssh.Unmarshal(request.Payload, &command)
							if command.Command == "test -f /opt/atlant-managed/native.json" {
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
								return
							}
							if stopped {
								_ = json.NewEncoder(channel).Encode(map[string]bool{"stopped": true})
							} else {
								_ = json.NewEncoder(channel).Encode(map[string]any{"panel_port": 19090, "entry_path": entry, "username": "admin", "password": "test-panel-secret"})
							}
							_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							return
						}
					}
				}()
			} else if incoming.ChannelType() == "direct-tcpip" {
				go ssh.DiscardRequests(requests)
				go func() {
					defer channel.Close()
					upstream, e := net.Dial("tcp", backend)
					if e != nil {
						return
					}
					defer upstream.Close()
					go io.Copy(upstream, channel)
					_, _ = io.Copy(channel, upstream)
				}()
			} else {
				channel.Close()
			}
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	raw, _ := json.Marshal(Request{Host: "127.0.0.1", Port: address.Port, Username: "root", Password: "test-ssh-secret", Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())})
	id, err := Begin(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer Close(id)
	var state State
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_ = json.Unmarshal([]byte(Status(id)), &state)
		if state.Phase == "ready" || state.Phase == "failed" || state.Phase == "stopped" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stopped {
		if state.Phase != "stopped" || generation.Load() != 0 {
			t.Fatal("stopped container caused a login attempt", state)
		}
		return
	}
	if state.Phase != "ready" {
		t.Fatalf("management not ready: %+v", state)
	}
	client := &http.Client{Transport: &http.Transport{}, Timeout: 3 * time.Second}
	response, err := client.Get(state.URL + "control/session")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), `"managed":true`) {
		t.Fatalf("proxy failed: %d %s", response.StatusCode, body)
	}
	if len(response.Cookies()) != 0 {
		t.Fatal("panel login cookie exposed to browser")
	}
	page, err := client.Get(state.URL)
	if err != nil {
		t.Fatal(err)
	}
	page.Body.Close()
	if page.StatusCode != 404 {
		t.Fatal("management bridge serves panel HTML")
	}
	// Simulate an expired remote session without closing the SSH connection.
	generation.Add(1)
	response, err = client.Get(state.URL + "control/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || generation.Load() != 3 {
		t.Fatal("expired embedded panel session was not renewed")
	}
	if len(response.Cookies()) != 0 {
		t.Fatal("renewal cookie exposed to browser")
	}
	result, err := Call(state.ID, `{"command":"status"}`)
	if err != nil || !strings.Contains(result, `"online":3`) {
		t.Fatal("native command over pinned SSH failed", result, err)
	}
	request, _ := http.NewRequest("GET", state.URL, nil)
	request.Header.Set("Origin", "https://untrusted.example")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("cross-origin management access accepted")
	}
	request, _ = http.NewRequest("GET", state.URL, nil)
	request.Host = "untrusted.example"
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("untrusted host accepted")
	}
}

func TestInvalidManagementRequestsNeverStart(t *testing.T) {
	for _, r := range []Request{{Host: "bad; command", Username: "root", Fingerprint: ""}, {Host: "example.com", Port: -1}, {Host: "example.com", Username: "root"}, {Host: "example.com", Username: "root", Fingerprint: "SHA256:test", Install: true, VPNPort: 443, PanelPort: 19090}} {
		data, _ := json.Marshal(r)
		if id, err := Begin(string(data)); err == nil {
			Close(id)
			t.Fatalf("accepted invalid request: %+v", r)
		}
	}
}

func TestMetadataBufferBounded(t *testing.T) {
	var b boundedBuffer
	if _, err := b.Write([]byte(strings.Repeat("x", 8192))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Fatal("unbounded metadata")
	}
}

func TestDockerBundleNoDefaultWebPortsOrPrivilegedMounts(t *testing.T) {
	entries, err := assets.ReadDir("assets")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("build caches must not be embedded in the client", entry.Name())
		}
	}
	script, _ := assets.ReadFile("assets/install.py")
	runtime, _ := assets.ReadFile("assets/runtime.py")
	bootstrap := string(runtime)
	if !strings.Contains(bootstrap, "os.setgroups([]);os.setgid(10001);os.setuid(10001)") ||
		!strings.Contains(bootstrap, "data[0]=Data(1<<10,1<<10,1<<10)") {
		t.Fatal("runtime must retain only low-port binding after dropping root")
	}
	if strings.Index(bootstrap, "if __name__=='__main__':drop_runtime_privileges()") > strings.Index(bootstrap, "from atlantctl import") {
		t.Fatal("private application modules must load after dropping root")
	}
	for _, capability := range []string{"NET_BIND_SERVICE", "SETUID", "SETGID"} {
		if !strings.Contains(string(script), "'--cap-add','"+capability+"'") {
			t.Fatal("missing constrained startup capability", capability)
		}
	}
	for _, bad := range []string{"docker.sock", "--privileged", "-p 80:", "-p 443:"} {
		if strings.Contains(string(script), bad) {
			t.Fatal("unsafe deployment", bad)
		}
	}
	if !strings.Contains(string(script), "'--cap-drop','ALL'") {
		t.Fatal("missing capability restriction")
	}
}
