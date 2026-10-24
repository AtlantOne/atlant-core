package main

import (
	"net"
	"sync"
)

// Limits include donor relays and authenticated connections, so a slow peer
// cannot keep unlimited sockets alive merely by leaving the handshake path.
type connectionBudget struct {
	mu sync.Mutex
	total int
	peers map[string]int
}

var acceptedConnections = connectionBudget{peers: make(map[string]int)}

func (b *connectionBudget) take(conn net.Conn) (net.Conn, bool) {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil { return nil, false }
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total >= 4096 || b.peers[host] >= 128 { return nil, false }
	b.total++; b.peers[host]++
	return &budgetConn{Conn:conn, release:func(){
		b.mu.Lock(); defer b.mu.Unlock()
		b.total--; b.peers[host]--
		if b.peers[host] == 0 { delete(b.peers,host) }
	}}, true
}

type budgetConn struct { net.Conn; once sync.Once; release func() }
func (c *budgetConn) Close() error { err:=c.Conn.Close(); c.once.Do(c.release); return err }
func (c *budgetConn) CloseWrite() error {
	if cw,ok:=c.Conn.(interface{CloseWrite() error});ok{return cw.CloseWrite()};return nil
}
