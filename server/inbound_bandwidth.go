package main

import (
	"atlant.local/protocol/wire"
	"net"
	"sync"
	"time"
)

type inboundBandwidth struct {
	id          string
	up, down    uint64
	tx, rx      *wire.FairPacer
	refs, flows int
	idle        *time.Timer
}

var bandwidthState = struct {
	sync.Mutex
	entries map[string]*inboundBandwidth
}{entries: make(map[string]*inboundBandwidth)}

func bandwidthID(c *Config) string {
	if c.InboundID != "" {
		return c.InboundID
	}
	return "@" + c.ServerAddr
}

// TCP, XHTTP and all QUIC carriers of one inbound share these budgets. Opening
// more carriers must not multiply an administrator's bandwidth limit.
func acquireInboundBandwidth(c *Config) (string, func()) {
	if c == nil {
		return "", func() {}
	}
	id, up, down := bandwidthID(c), c.GetUpMbps(), c.GetDownMbps()
	bandwidthState.Lock()
	b := bandwidthState.entries[id]
	if up == 0 && down == 0 {
		if b != nil {
			delete(bandwidthState.entries, id)
			retireBandwidthLocked(b)
		}
		bandwidthState.Unlock()
		return id, func() {}
	}
	if b == nil || b.up != up || b.down != down {
		b = &inboundBandwidth{id: id, up: up, down: down}
		bandwidthState.entries[id] = b
	}
	b.refs++
	bandwidthState.Unlock()
	var once sync.Once
	return id, func() {
		once.Do(func() {
			bandwidthState.Lock()
			b.refs--
			retireBandwidthLocked(b)
			bandwidthState.Unlock()
		})
	}
}

func retireBandwidthLocked(b *inboundBandwidth) {
	if b.refs != 0 || b.flows != 0 {
		return
	}
	if bandwidthState.entries[b.id] == b {
		delete(bandwidthState.entries, b.id)
	}
	if b.idle != nil {
		b.idle.Stop()
	}
	b.tx.Close()
	b.rx.Close()
}

func paceServerTarget(conn net.Conn, packet bool, ids ...string) net.Conn {
	return paceInboundConn(conn, packet, false, ids...)
}

// Diagnostic streams face the client rather than the destination socket.
func paceInboundStream(conn streamConn, ids ...string) net.Conn {
	return paceInboundConn(bandwidthStream{conn}, false, true, ids...)
}

type bandwidthStream struct{ streamConn }

func (c bandwidthStream) LocalAddr() net.Addr  { return wire.StreamAddr(nil) }
func (c bandwidthStream) RemoteAddr() net.Addr { return wire.StreamAddr(nil) }
func (c bandwidthStream) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func paceInboundConn(conn net.Conn, packet, reverse bool, ids ...string) net.Conn {
	id := ""
	if len(ids) > 0 {
		id = ids[0]
	}
	if id == "" && cfg != nil {
		id = bandwidthID(cfg)
	}
	bandwidthState.Lock()
	b := bandwidthState.entries[id]
	if b == nil {
		bandwidthState.Unlock()
		return conn
	}
	if b.idle != nil {
		b.idle.Stop()
		b.idle = nil
	}
	if b.tx == nil && b.up > 0 {
		b.tx = wire.NewFairPacer(b.up)
	}
	if b.rx == nil && b.down > 0 {
		b.rx = wire.NewFairPacer(b.down)
	}
	b.flows++
	read, write := b.tx, b.rx
	if reverse {
		read, write = write, read
	}
	bandwidthState.Unlock()
	return wire.PaceConn(conn, read, write, packet, func() {
		bandwidthState.Lock()
		defer bandwidthState.Unlock()
		b.flows--
		if b.flows == 0 {
			if b.refs == 0 {
				retireBandwidthLocked(b)
				return
			}
			b.idle = time.AfterFunc(time.Minute, func() {
				bandwidthState.Lock()
				defer bandwidthState.Unlock()
				if b.flows == 0 {
					b.tx.Close()
					b.rx.Close()
					b.tx, b.rx = nil, nil
				}
			})
		}
	})
}
