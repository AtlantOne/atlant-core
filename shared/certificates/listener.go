package certificates

import (
	"net"
	"sync"
)

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConnection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConnection{Conn: conn, slots: l.slots}, nil
		default:
			_ = conn.Close()
		}
	}
}

// LimitListener bounds the number of HTTP connections before net/http creates
// workers, including sockets that have not sent a request header yet.
func LimitListener(listener net.Listener, limit int) net.Listener {
	if limit < 1 {
		panic("HTTP connection limit must be positive")
	}
	return &limitedListener{Listener: listener, slots: make(chan struct{}, limit)}
}
