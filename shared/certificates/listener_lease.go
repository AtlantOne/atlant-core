package certificates

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// challengeLease shares HTTP-01 only between active issuance attempts, not
// between idle renewal workers. The last attempt releases the listening port.
type challengeLease struct {
	mu      sync.Mutex
	listen  func(string, string) (net.Listener, error)
	address string
	handler http.Handler
	server  *http.Server
	socket  net.Listener
	users   int
}

func (b *challengeLease) acquire() (func(), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.server == nil {
		ln, err := b.listen("tcp", b.address)
		if err != nil {
			return nil, err
		}
		b.server = &http.Server{Handler: b.handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
		server := b.server
		b.socket = ln
		go server.Serve(LimitListener(ln, 64))
	}
	b.users++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.users--
			if b.users == 0 {
				_ = b.socket.Close()
				_ = b.server.Close()
				b.server = nil
				b.socket = nil
			}
		})
	}, nil
}

func (b *challengeLease) listening() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.server != nil }
