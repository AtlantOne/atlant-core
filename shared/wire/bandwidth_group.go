package wire

import (
	"net"
	"sync"
)

// BandwidthGroup is shared by transports in a single client session.
type BandwidthGroup struct {
	mu       sync.Mutex
	key      string
	up, down uint64
	tx, rx   *FairPacer
}

func (g *BandwidthGroup) Wrap(key string, up, down uint64, c net.Conn, udp, reverse bool) net.Conn {
	if up == 0 && down == 0 {
		return c
	}
	g.mu.Lock()
	if key != g.key || up != g.up || down != g.down {
		g.tx.Close()
		g.rx.Close()
		g.tx, g.rx = NewFairPacer(up), NewFairPacer(down)
		g.key, g.up, g.down = key, up, down
	}
	read, write := g.rx, g.tx
	if reverse {
		read, write = write, read
	}
	g.mu.Unlock()
	return PaceConn(c, read, write, udp, nil)
}

func (g *BandwidthGroup) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tx.Close()
	g.rx.Close()
	g.tx, g.rx = nil, nil
	g.key = ""
	g.up, g.down = 0, 0
}
