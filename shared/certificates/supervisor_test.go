package certificates

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSupervisorRetainsJobsOnBadConfigAndAdoptsValidEdits(t *testing.T) {
	initial := cachedAgent(t).config
	path := filepath.Join(t.TempDir(), "config.json")
	save := func(config AgentConfig) {
		data, _ := json.Marshal(config)
		if err := writePrivateAtomic(path, data); err != nil {
			t.Fatal(err)
		}
	}
	save(initial)
	supervisor := supervisor{interval: 10 * time.Millisecond, makeAgent: func(config AgentConfig) (*Agent, error) {
		agent, err := NewAgent(config)
		if err == nil {
			agent.listener = func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
		}
		return agent, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.run(ctx, path) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("supervisor did not stop")
		}
	}()
	wait := func(predicate func(map[string]map[string]any) bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			var report struct{ Jobs map[string]map[string]any }
			if data, err := os.ReadFile(filepath.Join(initial.StateDir, "status.json")); err == nil && json.Unmarshal(data, &report) == nil && predicate(report.Jobs) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("supervisor state transition missing")
	}
	wait(func(jobs map[string]map[string]any) bool {
		return jobs["panel"]["not_after"] != nil && jobs["agent"]["phase"] == "running"
	})
	if err := writePrivateAtomic(path, []byte(`{"broken":true}`)); err != nil {
		t.Fatal(err)
	}
	wait(func(jobs map[string]map[string]any) bool {
		return jobs["agent"]["configuration_error"] != nil && jobs["panel"]["not_after"] != nil
	})
	save(initial)
	wait(func(jobs map[string]map[string]any) bool {
		return jobs["agent"]["configuration_error"] == nil && jobs["agent"]["phase"] == "running"
	})
	updated := initial
	updated.Jobs = append([]Job(nil), initial.Jobs...)
	updated.Jobs[0].ID = "renamed"
	save(updated)
	wait(func(jobs map[string]map[string]any) bool {
		return jobs["renamed"]["not_after"] != nil && jobs["panel"] == nil && jobs["agent"]["phase"] == "running"
	})
	updated.Jobs = []Job{}
	save(updated)
	wait(func(jobs map[string]map[string]any) bool {
		return len(jobs) == 1 && jobs["agent"]["phase"] == "running"
	})
}
