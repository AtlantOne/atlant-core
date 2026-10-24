package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/gofrs/flock"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID  string `json:"id"`
	TLS Config `json:"tls"`
}

type AgentConfig struct {
	StateDir        string `json:"state_dir"`
	ChallengeListen string `json:"challenge_listen"`
	Jobs            []Job  `json:"jobs"`
}

func (c AgentConfig) Validate() error {
	if !filepath.IsAbs(c.StateDir) || c.Jobs == nil || len(c.Jobs) > 16 {
		return errors.New("absolute agent state directory and an explicit list of 0-16 certificate jobs required")
	}
	host, port, err := net.SplitHostPort(c.ChallengeListen)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || (port != "80" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return errors.New("HTTP-01 requires public port 80 or a literal loopback listener behind a port-80 reverse proxy")
	}
	ids, caches, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, job := range c.Jobs {
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(job.ID) || ids[job.ID] || job.ID == "agent" {
			return errors.New("certificate job IDs must be unique ASCII names")
		}
		if err := Validate(job.TLS); err != nil {
			return err
		}
		if job.TLS.Mode == "manual" {
			return errors.New("manual certificates are reloaded by the panel; the agent only issues ACME certificates")
		}
		cache := filepath.Clean(job.TLS.CacheDir)
		host := strings.ToLower(job.TLS.Host)
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		}
		if caches[cache] || hosts[host] {
			return errors.New("use one certificate job per hostname/IP and cache; HTTPS services may share its bundle")
		}
		ids[job.ID], caches[cache], hosts[host] = true, true, true
	}
	return nil
}

type Agent struct {
	config      AgentConfig
	mu          sync.Mutex
	status      map[string]map[string]any
	listener    func(string, string) (net.Listener, error)
	configError string
}

func NewAgent(config AgentConfig) (*Agent, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Agent{config: config, status: map[string]map[string]any{}, listener: net.Listen}, nil
}

func (a *Agent) publish(id string, status map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.status[id] = status
	if id == "agent" && a.configError != "" {
		status["configuration_error"] = a.configError
	}
	data, err := json.Marshal(map[string]any{"version": 1, "updated_at": time.Now().UTC(), "jobs": a.status})
	if err != nil {
		return err
	}
	return writePrivateAtomic(filepath.Join(a.config.StateDir, "status.json"), data)
}

// Run owns only HTTP-01 and certificate state. It never starts/stops a VPN,
// modifies firewall rules or proxies traffic to the management application.
func (a *Agent) Run(ctx context.Context) error {
	if err := privateDirectory(a.config.StateDir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(a.config.StateDir, ".agent.lock"), flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		_ = lock.Close()
		return errors.New("certificate agent already running or state directory locked")
	}
	defer lock.Close()
	challengeDir := filepath.Join(a.config.StateDir, "challenges")
	if err := privateDirectory(challengeDir); err != nil {
		return err
	}
	listener, err := a.listener("tcp", a.config.ChallengeListen)
	if err != nil {
		_ = a.publish("agent", map[string]any{"error": "HTTP-01 port unavailable; no existing service was changed"})
		return errors.New("HTTP-01 port unavailable; configure one shared broker or release port 80 explicitly")
	}
	server := &http.Server{Handler: ChallengeBroker(challengeDir), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	defer server.Close()
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(LimitListener(listener, 64)) }()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	pool := make(chan struct{}, 2)
	workerErrors := make(chan error, len(a.config.Jobs))
	for _, job := range a.config.Jobs {
		workers.Add(1)
		go func(job Job) {
			defer workers.Done()
			if err := a.runJob(workerCtx, job, challengeDir, pool); err != nil {
				workerErrors <- err
			}
		}(job)
	}
	if err = a.publish("agent", map[string]any{"phase": "running", "listening": true}); err != nil {
		cancel()
		workers.Wait()
		return err
	}
	heartbeat := time.NewTicker(time.Minute)
	defer heartbeat.Stop()
running:
	for {
		select {
		case <-ctx.Done():
			err = nil
			_ = a.publish("agent", map[string]any{"phase": "stopped", "listening": false})
			break running
		case err = <-serveErrors:
			_ = a.publish("agent", map[string]any{"error": "HTTP-01 listener stopped"})
			break running
		case err = <-workerErrors:
			break running
		case <-heartbeat.C:
			if err = a.publish("agent", map[string]any{"phase": "running", "listening": true}); err != nil {
				break running
			}
		}
	}
	cancel()
	workers.Wait()
	return err
}

func (a *Agent) runJob(ctx context.Context, job Job, challengeDir string, pool chan struct{}) error {
	options := job.TLS
	options.ChallengeDir = challengeDir
	options.RequireContext = true
	manager := New(options)
	_ = manager.Reload()
	delay := time.Minute
	for {
		if manager.RenewalDue(time.Now()) {
			status := manager.Status()
			status["host"] = options.Host
			status["phase"] = "issuing"
			if err := a.publish(job.ID, status); err != nil {
				return err
			}
			select {
			case pool <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			attempt, cancel := context.WithTimeout(ctx, 5*time.Minute)
			err := manager.Ensure(attempt)
			cancel()
			<-pool
			if err != nil {
				status := manager.Status()
				status["host"] = options.Host
				status["next_attempt"] = time.Now().Add(delay).UTC()
				if err := a.publish(job.ID, status); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(delay):
				}
				if delay < time.Hour {
					delay *= 2
					if delay > time.Hour {
						delay = time.Hour
					}
				}
				continue
			}
		}
		delay = time.Minute
		status := manager.Status()
		status["host"] = options.Host
		status["bundle"] = manager.BundlePath()
		if err := a.publish(job.ID, status); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Minute):
		}
	}
}
