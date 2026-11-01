package certificates

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestChallengeLeaseReleasesLastAttempt(t *testing.T) {
	var address string
	broker := &challengeLease{address: "127.0.0.1:0", handler: http.NotFoundHandler(), listen: func(network, addr string) (net.Listener, error) {
		ln, err := net.Listen(network, addr)
		if err == nil {
			address = ln.Addr().String()
		}
		return ln, err
	}}
	if broker.listening() {
		t.Fatal("idle broker listens")
	}
	one, err := broker.acquire()
	if err != nil {
		t.Fatal(err)
	}
	two, err := broker.acquire()
	if err != nil {
		t.Fatal(err)
	}
	one()
	one()
	if !broker.listening() {
		t.Fatal("closed during concurrent issuance")
	}
	two()
	if broker.listening() {
		t.Fatal("port retained after last issuance")
	}
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal("port not released", err)
	}
	ln.Close()
}

func TestAgentNoJobsDoesNotBind(t *testing.T) {
	agent, err := NewAgent(AgentConfig{StateDir: t.TempDir(), ChallengeListen: ":80", Jobs: []Job{}})
	if err != nil {
		t.Fatal(err)
	}
	agent.listener = func(string, string) (net.Listener, error) {
		t.Error("idle agent attempted to bind")
		return nil, context.Canceled
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := agent.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
