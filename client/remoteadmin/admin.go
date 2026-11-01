// Package remoteadmin installs an isolated Docker server over pinned SSH and
// connects the clients' management screens to a private JSON API over SSH.
package remoteadmin

import (
	"bufio"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed assets/runtime.py assets/install.py assets/native-update.py assets/native-panel.py
var assets embed.FS

type Request struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	PrivateKey    string `json:"private_key,omitempty"`
	Fingerprint   string `json:"fingerprint"`
	VPNPort       int    `json:"vpn_port"`
	PanelPort     int    `json:"panel_port"`
	Install       bool   `json:"install"`
	InstallDocker bool   `json:"install_docker"`
}

type State struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	URL   string `json:"url,omitempty"`
	Error string `json:"error,omitempty"`
}
type job struct {
	mu          sync.Mutex
	operationMu sync.Mutex
	csrf        string
	state       State
	cancel      context.CancelFunc
	client      *ssh.Client
	server      *http.Server
	nativeInput io.WriteCloser
}

var jobs = struct {
	sync.Mutex
	items map[string]*job
}{items: map[string]*job{}}

func endpoint(host string, port int) (string, error) {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\\r\n\t @?#") {
		return "", errors.New("invalid SSH host")
	}
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid SSH port")
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port)), nil
}

// Probe only obtains the SSH host key; no password is sent. The UI must show
// this fingerprint and ask for first-use confirmation before Begin.
func Probe(host string, port int) (string, error) {
	address, err := endpoint(host, port)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return "", errors.New("SSH endpoint unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	var fingerprint string
	_, _, _, err = ssh.NewClientConn(conn, address, &ssh.ClientConfig{User: "probe", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		return errors.New("host-key probe complete")
	}})
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", errors.New("SSH host-key probe failed")
}

func Begin(raw string) (string, error) {
	if len(raw) > 128<<10 {
		return "", errors.New("request too large")
	}
	var request Request
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		return "", errors.New("invalid request")
	}
	if _, err := endpoint(request.Host, request.Port); err != nil {
		return "", err
	}
	if request.Username == "" || len(request.Username) > 64 || !strings.HasPrefix(request.Fingerprint, "SHA256:") {
		return "", errors.New("SSH login and confirmed host fingerprint required")
	}
	if request.VPNPort == 0 {
		request.VPNPort = 1026
	}
	if request.PanelPort == 0 {
		request.PanelPort = 19090
	}
	if request.Install && (request.VPNPort < 1024 || request.PanelPort < 1024 || request.VPNPort > 65535 || request.PanelPort > 65535 || request.VPNPort == request.PanelPort) {
		return "", errors.New("invalid installation ports")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(nonce[:])
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{state: State{ID: id, Phase: "connecting"}, cancel: cancel}
	jobs.Lock()
	if len(jobs.items) >= 16 {
		jobs.Unlock()
		cancel()
		return "", errors.New("close an existing management session first")
	}
	jobs.items[id] = j
	jobs.Unlock()
	go func() {
		deadline := time.AfterFunc(45*time.Minute, cancel)
		defer deadline.Stop()
		if err := j.run(ctx, request); err != nil {
			j.mu.Lock()
			j.state.Phase = "failed"
			j.state.Error = err.Error()
			j.mu.Unlock()
			cancel()
		}
	}()
	return id, nil
}

func Status(id string) string {
	jobs.Lock()
	j := jobs.items[id]
	jobs.Unlock()
	if j == nil {
		return `{"phase":"missing"}`
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	data, _ := json.Marshal(j.state)
	return string(data)
}
func Close(id string) {
	jobs.Lock()
	j := jobs.items[id]
	delete(jobs.items, id)
	jobs.Unlock()
	if j == nil {
		return
	}
	j.cancel()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.server != nil {
		j.server.Close()
	}
	if j.nativeInput != nil {
		j.nativeInput.Close()
	}
	if j.client != nil {
		j.client.Close()
	}
}
func (j *job) phase(value string) { j.mu.Lock(); j.state.Phase = value; j.mu.Unlock() }

func (j *job) run(ctx context.Context, r Request) error {
	address, _ := endpoint(r.Host, r.Port)
	auth := []ssh.AuthMethod{ssh.Password(r.Password)}
	if r.PrivateKey != "" {
		key, err := ssh.ParsePrivateKey([]byte(r.PrivateKey))
		if err != nil {
			return errors.New("invalid or encrypted SSH private key")
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	}
	config := &ssh.ClientConfig{User: r.Username, Auth: auth, Timeout: 12 * time.Second, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != r.Fingerprint {
			return errors.New("SSH host key changed")
		}
		return nil
	}}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return errors.New("SSH endpoint unavailable")
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, requests, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return errors.New("SSH authentication or pinned host-key check failed")
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, requests)
	// Keep idle management sessions alive through NATs. Closing the connection
	// also unblocks a stalled keepalive request.
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				done := make(chan error, 1)
				go func() { _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); done <- err }()
				select {
				case err := <-done:
					if err != nil {
						j.cancel()
						return
					}
				case <-time.After(12 * time.Second):
					j.cancel()
					return
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	j.mu.Lock()
	j.client = client
	j.mu.Unlock()
	go func() { _ = client.Wait(); j.cancel() }()
	go func() {
		<-ctx.Done()
		j.mu.Lock()
		input := j.nativeInput
		j.mu.Unlock()
		if input != nil {
			input.Close()
		}
		client.Close()
		j.mu.Lock()
		if j.server != nil {
			j.server.Close()
		}
		if j.state.Phase == "ready" {
			j.state.Phase = "closed"
			j.state.URL = ""
		}
		j.mu.Unlock()
	}()
	if r.Install {
		j.phase("preparing")
		var secret [24]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return err
		}
		files := map[string]string{}
		for _, name := range []string{"runtime.py", "native-update.py", "native-panel.py"} {
			data, _ := assets.ReadFile("assets/" + name)
			files[name] = string(data)
		}
		input, _ := json.Marshal(map[string]any{"host": r.Host, "vpn_port": r.VPNPort, "panel_port": r.PanelPort, "password": hex.EncodeToString(secret[:]), "files": files, "install_docker": r.InstallDocker})
		script, _ := assets.ReadFile("assets/install.py")
		// Script and configuration are supplied through stdin, not shell argv.
		// The fixed Python launcher reads exactly the script length, then execs it
		// with the remaining stdin reserved for private installation JSON.
		launch := fmt.Sprintf("python3 -c 'import sys; code=sys.stdin.buffer.read(%d); exec(compile(code,\"<atlant-install>\",\"exec\"))'", len(script))
		session, err := client.NewSession()
		if err != nil {
			return errors.New("SSH command unavailable")
		}
		defer session.Close()
		session.Stdin = io.MultiReader(strings.NewReader(string(script)), strings.NewReader(string(input)))
		session.Stdout = &installProgress{job: j}
		var diagnostic installDiagnostic
		session.Stderr = &diagnostic
		j.phase("installing")
		if err := session.Run(launch); err != nil {
			message := strings.TrimSpace(string(diagnostic.data))
			message = strings.SplitN(message, "\n", 2)[0]
			if message == "" {
				message = "Server installation/update failed; existing persistent data was preserved"
			}
			return errors.New(message)
		}
	}
	j.phase("opening")
	metadata, err := j.accessMetadata(ctx, client)
	if err != nil {
		return errors.New("managed server metadata unavailable; choose Install for a new server")
	}
	var access struct {
		Port     int    `json:"panel_port"`
		Path     string `json:"entry_path"`
		Username string `json:"username"`
		Password string `json:"password"`
		Stopped  bool   `json:"stopped"`
	}
	if json.Unmarshal(metadata, &access) != nil {
		return errors.New("invalid managed server metadata")
	}
	if access.Stopped {
		j.phase("stopped")
		j.cancel()
		return nil
	}
	if access.Port < 1024 || access.Port > 65535 || len(access.Path) != 34 || access.Path[0] != '/' || access.Path[33] != '/' {
		return errors.New("invalid managed server metadata")
	}
	for _, ch := range access.Path[1:33] {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", ch) {
			return errors.New("invalid panel entry path")
		}
	}
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(access.Port))
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return client.DialContext(ctx, "tcp", target)
	}, ResponseHeaderTimeout: 30 * time.Second, MaxIdleConnsPerHost: 8}
	login, _ := json.Marshal(map[string]string{"username": access.Username, "password": access.Password})
	var cookieMu sync.Mutex
	var cookies []*http.Cookie
	// Called before serving, or while cookieMu is held during session renewal.
	authenticate := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+target+access.Path+"control/login", strings.NewReader(string(login)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://"+target)
		response, err := (&http.Client{Transport: transport, Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			return errors.New("panel unavailable through SSH")
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
		response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("panel login failed; credentials may have been changed through the panel CLI")
		}
		cookies = response.Cookies()
		return nil
	}
	if err := authenticate(ctx); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	local := listener.Addr().String()
	proxy := &httputil.ReverseProxy{Transport: transport, Director: func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = target
		req.Host = target
		if req.Header.Get("Origin") != "" {
			req.Header.Set("Origin", "http://"+target)
		}
		req.Header.Del("Forwarded")
		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Forwarded-Host")
	}, ModifyResponse: func(response *http.Response) error {
		// Reopening the embedded panel after its idle timeout must obtain a new
		// CSRF token, rather than expose an unusable login screen. Only this safe
		// session read is retried; mutations are never replayed.
		if response.StatusCode == 401 && response.Request.Method == http.MethodGet && response.Request.URL.Path == access.Path+"control/session" {
			cookieMu.Lock()
			defer cookieMu.Unlock()
			retry := func() (*http.Response, error) {
				req := response.Request.Clone(response.Request.Context())
				req.Header = response.Request.Header.Clone()
				req.Header.Del("Cookie")
				req.RequestURI = ""
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				return transport.RoundTrip(req)
			}
			fresh, err := retry()
			if err != nil {
				return err
			}
			if fresh.StatusCode == 401 {
				fresh.Body.Close()
				if err = authenticate(response.Request.Context()); err != nil {
					return err
				}
				fresh, err = retry()
				if err != nil {
					return err
				}
			}
			response.Body.Close()
			*response = *fresh
		}
		response.Header.Del("Set-Cookie")
		return nil
	}, ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "SSH management channel unavailable", 502)
	}}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 45 * time.Second, MaxHeaderBytes: 16 << 10}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != local || !strings.HasPrefix(req.URL.Path, access.Path) || req.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.NotFound(w, req)
			return
		}
		if origin := req.Header.Get("Origin"); origin != "" && origin != "http://"+local {
			http.Error(w, "forbidden origin", 403)
			return
		}
		route := strings.TrimPrefix(req.URL.Path, access.Path)
		if !((route == "control/session" && req.Method == http.MethodGet) || ((route == "control/prepare" || route == "control/commit") && req.Method == http.MethodPost)) {
			http.NotFound(w, req)
			return
		}
		// Cookies stay server-side. A random panel path is the local capability;
		// the panel still performs its own session and CSRF checks.
		req.Header.Del("Cookie")
		cookieMu.Lock()
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		cookieMu.Unlock()
		proxy.ServeHTTP(w, req)
	})
	j.mu.Lock()
	j.server = server
	j.state.URL = "http://" + local + access.Path
	j.state.Phase = "ready"
	j.mu.Unlock()
	go func() { _ = server.Serve(listener); transport.CloseIdleConnections() }()
	return nil
}

func (j *job) accessMetadata(ctx context.Context, client *ssh.Client) ([]byte, error) {
	probe, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	native := probe.Run("test -f /opt/atlant-managed/native.json") == nil
	probe.Close()
	if !native {
		session, err := client.NewSession()
		if err != nil {
			return nil, err
		}
		defer session.Close()
		var metadata boundedBuffer
		session.Stdout = &metadata
		session.Stderr = io.Discard
		command := `python3 -c 'import json,pathlib,subprocess; a=json.loads(pathlib.Path("/opt/atlant-managed/data/admin-access.json").read_text()); running=subprocess.check_output(["docker","inspect","--format","{{.State.Running}}","atlant-managed"],timeout=10).strip()==b"true"; print(json.dumps(a if running else {"stopped":True}))'`
		if err = session.Run(command); err != nil {
			return nil, err
		}
		return metadata.data, nil
	}
	script, _ := assets.ReadFile("assets/native-panel.py")
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	input, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	output, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, err
	}
	session.Stderr = io.Discard
	launch := fmt.Sprintf("python3 -c 'import sys; code=sys.stdin.buffer.read(%d); exec(compile(code,\"<atlant-native-panel>\",\"exec\"))'", len(script))
	if err = session.Start(launch); err != nil {
		session.Close()
		return nil, err
	}
	j.mu.Lock()
	j.nativeInput = input
	j.mu.Unlock()
	if _, err = input.Write(script); err != nil {
		input.Close()
		session.Close()
		return nil, err
	}
	type result struct {
		data []byte
		err  error
	}
	ready := make(chan result, 1)
	go func() {
		line, e := bufio.NewReader(io.LimitReader(output, 8193)).ReadBytes('\n')
		if len(line) > 8192 {
			e = errors.New("native metadata too large")
		}
		ready <- result{line, e}
	}()
	select {
	case value := <-ready:
		if value.err != nil {
			input.Close()
			session.Close()
			return nil, value.err
		}
		go io.Copy(io.Discard, output)
		go func() { _ = session.Wait(); j.cancel() }()
		return value.data, nil
	case <-ctx.Done():
		input.Close()
		session.Close()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		input.Close()
		session.Close()
		return nil, errors.New("native management session startup timed out")
	}
}

type installProgress struct {
	job  *job
	tail string
}

func (p *installProgress) Write(data []byte) (int, error) {
	text := p.tail + string(data)
	if strings.Contains(text, "Updating existing ") {
		p.job.phase("updating")
	}
	if len(text) > 128 {
		text = text[len(text)-128:]
	}
	p.tail = text
	return len(data), nil
}

type installDiagnostic struct{ data []byte }

func (b *installDiagnostic) Write(data []byte) (int, error) {
	n := len(data)
	remaining := 1024 - len(b.data)
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		b.data = append(b.data, data...)
	}
	return n, nil
}

type boundedBuffer struct{ data []byte }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 8192 {
		return 0, errors.New("metadata too large")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

var githubClient = &http.Client{Timeout: 20 * time.Second}

func githubJSON(ctx context.Context, path string, value any) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/AtlantOne/atlant-"+path, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := githubClient.Do(req)
	if err != nil {
		return 0, errors.New("GitHub release lookup unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return 404, nil
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(value) != nil {
		return resp.StatusCode, errors.New("could not read published release metadata")
	}
	return resp.StatusCode, nil
}

func revision(ctx context.Context, repo string) (string, error) {
	if repo != "core" && repo != "panel" {
		return "", errors.New("unknown release repository")
	}
	type release struct {
		Tag   string `json:"tag_name"`
		Draft bool   `json:"draft"`
	}
	var latest release
	status, err := githubJSON(ctx, repo+"/releases/latest", &latest)
	if err != nil {
		return "", err
	}
	if status == 404 {
		var previews []release
		if _, err = githubJSON(ctx, repo+"/releases?per_page=1", &previews); err != nil {
			return "", err
		}
		if len(previews) != 1 {
			return "", errors.New("no published release available")
		}
		latest = previews[0]
	}
	if latest.Draft || latest.Tag == "" || len(latest.Tag) > 128 {
		return "", errors.New("invalid published release tag")
	}
	var result struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if status, err = githubJSON(ctx, repo+"/git/ref/tags/"+url.PathEscape(latest.Tag), &result); err != nil || status != 200 {
		return "", errors.New("could not pin source revision")
	}
	sha, kind := result.Object.SHA, result.Object.Type
	for depth := 0; depth < 4; depth++ {
		if len(sha) != 40 {
			return "", errors.New("invalid source revision")
		}
		for _, ch := range sha {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return "", errors.New("invalid source revision")
			}
		}
		if kind == "commit" {
			return sha, nil
		}
		if kind != "tag" {
			break
		}
		if status, err = githubJSON(ctx, repo+"/git/tags/"+sha, &result); err != nil || status != 200 {
			return "", errors.New("could not resolve release tag")
		}
		sha, kind = result.Object.SHA, result.Object.Type
	}
	return "", errors.New("release tag does not resolve to a commit")
}
