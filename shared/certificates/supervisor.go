package certificates

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

func LoadAgentConfig(path string) (AgentConfig, string, error) {
	var config AgentConfig
	file, err := os.Open(path)
	if err != nil {
		return config, "", errors.New("certificate agent configuration unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 || (os.PathSeparator == '/' && info.Mode().Perm()&0007 != 0) {
		return config, "", errors.New("certificate configuration must be a private regular file below 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return config, "", errors.New("certificate configuration too large or unreadable")
	}
	sum := sha256.Sum256(data)
	revision := hex.EncodeToString(sum[:])
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(&config) != nil || decoder.Decode(&extra) != io.EOF {
		return config, revision, errors.New("invalid certificate agent configuration")
	}
	return config, revision, config.Validate()
}

type supervisor struct {
	makeAgent func(AgentConfig) (*Agent, error)
	interval  time.Duration
}

// RunConfigFile adopts valid configuration changes without privileged service
// restarts. Invalid edits leave the running jobs in place. Rebinding the broker
// or moving agent state requires an explicit service restart instead.
func RunConfigFile(ctx context.Context, path string) error {
	return (supervisor{makeAgent: NewAgent, interval: time.Second}).run(ctx, path)
}

func (s supervisor) run(ctx context.Context, path string) error {
	config, revision, err := LoadAgentConfig(path)
	if err != nil {
		return err
	}
	agent, err := s.makeAgent(config)
	if err != nil {
		return err
	}
	start := func(agent *Agent) (context.CancelFunc, chan error) {
		child, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- agent.Run(child) }()
		return cancel, done
	}
	cancel, done := start(agent)
	defer func() { cancel() }()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			return <-done
		case err := <-done:
			return err
		case <-ticker.C:
			candidate, next, loadErr := LoadAgentConfig(path)
			if next == revision && loadErr == nil {
				agent.mu.Lock()
				changed := agent.configError != ""
				agent.configError = ""
				agent.mu.Unlock()
				if changed {
					if err := agent.publish("agent", map[string]any{"phase": "running", "listening": true}); err != nil {
						cancel()
						<-done
						return err
					}
				}
				continue
			}
			if loadErr == nil && (candidate.StateDir != config.StateDir || candidate.ChallengeListen != config.ChallengeListen) {
				loadErr = errors.New("broker address or state changes require an explicit service restart")
			}
			if loadErr != nil {
				agent.mu.Lock()
				changed := agent.configError == ""
				agent.configError = "Certificate settings rejected; previous jobs retained"
				agent.mu.Unlock()
				if changed {
					if err := agent.publish("agent", map[string]any{"phase": "running", "listening": true}); err != nil {
						cancel()
						<-done
						return err
					}
				}
				continue
			}
			replacement, err := s.makeAgent(candidate)
			if err != nil {
				continue
			}
			cancel()
			if err := <-done; err != nil {
				return err
			}
			agent, config, revision = replacement, candidate, next
			cancel, done = start(agent)
		}
	}
}
