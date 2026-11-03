package main

import (
	"atlant.local/protocol/wire"
	"context"
	"crypto/hmac"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type udpDatagramFlow struct {
	queue  chan []byte
	ctx    context.Context
	cancel context.CancelFunc
	active atomic.Int64
}

func relayQUICDatagrams(ctx context.Context, conn *quic.Conn, pacer *BrutalPacer, user string) {
	relayDatagramFlows(ctx, conn.ReceiveDatagram, conn.SendDatagram, pacer, user, safeResolveUDPContext)
}

// Each destination owns its socket and a bounded queue. Resolution and writes
// cannot block reception for another flow on the same authenticated carrier.
func relayDatagramFlows(ctx context.Context, receive func(context.Context) ([]byte, error), send func([]byte) error, pacer *BrutalPacer, user string, resolve func(context.Context, string) (*net.UDPAddr, error)) {
	ctx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	var workers sync.WaitGroup
	var queuedBytes atomic.Int64
	flows := make(map[string]*udpDatagramFlow)
	resolvers := make(chan struct{}, 16)
	defer func() {
		cancel()
		workers.Wait()
	}()
	var assembler wire.DatagramAssembler
	tag := getUserTag(user)
	for {
		packet, err := receive(ctx)
		if err != nil {
			return
		}
		packet, complete := assembler.Decode(packet, 8, time.Now())
		if !complete || len(packet) < 10 || !hmac.Equal(packet[:4], tag[:]) {
			continue
		}
		destLen := int(binary.BigEndian.Uint16(packet[8:10]) & wire.DatagramDestinationMask)
		supportsFragments := binary.BigEndian.Uint16(packet[8:10])&wire.DatagramFragmentsSupported != 0
		if destLen < 1 || destLen > 512 || len(packet) < 10+destLen {
			continue
		}
		flowID := binary.BigEndian.Uint32(packet[4:8])
		target := string(packet[10 : 10+destLen])
		payload := packet[10+destLen:]
		if !recordUserTraffic(user, uint64(len(payload)), 0) {
			return
		}
		key := string(packet[4:8]) + target
		mu.Lock()
		flow := flows[key]
		if flow == nil {
			if len(flows) >= 1024 {
				mu.Unlock()
				continue
			}
			flowCtx, flowCancel := context.WithCancel(ctx)
			flow = &udpDatagramFlow{queue: make(chan []byte, 16), ctx: flowCtx, cancel: flowCancel}
			flow.active.Store(time.Now().UnixNano())
			flows[key] = flow
			workers.Add(1)
			go func(flow *udpDatagramFlow, key, target string, flowID uint32, supportsFragments bool) {
				defer workers.Done()
				defer func() {
					flow.cancel()
					mu.Lock()
					delete(flows, key)
					mu.Unlock()
					for {
						select {
						case p := <-flow.queue:
							queuedBytes.Add(-int64(len(p)))
						default:
							return
						}
					}
				}()
				resolveCtx, stopResolve := context.WithTimeout(flow.ctx, 3*time.Second)
				select {
				case resolvers <- struct{}{}:
				case <-resolveCtx.Done():
					stopResolve()
					return
				}
				address, err := resolve(resolveCtx, target)
				<-resolvers
				stopResolve()
				if err != nil {
					log.Printf("[QUIC-DGRAM] UDP resolution failed for %s: %v", target, err)
					return
				}
				if flow.ctx.Err() != nil {
					return
				}
				socket, err := net.DialUDP("udp", nil, address)
				if err != nil {
					log.Printf("[QUIC-DGRAM] UDP dial failed for %s: %v", target, err)
					return
				}
				defer socket.Close()
				_ = socket.SetReadBuffer(256 * 1024)
				_ = socket.SetWriteBuffer(256 * 1024)
				readerDone := make(chan struct{})
				go func() {
					defer close(readerDone)
					defer flow.cancel()
					buffer := make([]byte, 65536)
					reportedSendError := false
					for {
						_ = socket.SetReadDeadline(time.Now().Add(60 * time.Second))
						n, err := socket.Read(buffer)
						if err != nil {
							if timeout, ok := err.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, flow.active.Load())) < 60*time.Second {
								continue
							}
							return
						}
						flow.active.Store(time.Now().UnixNano())
						response := dnsUDPResponse(target, buffer[:n])
						if !recordUserTraffic(user, 0, uint64(len(response))) {
							return
						}
						packet := make([]byte, 6+len(target)+len(response))
						binary.BigEndian.PutUint32(packet[:4], flowID)
						binary.BigEndian.PutUint16(packet[4:6], uint16(len(target)))
						copy(packet[6:], target)
						copy(packet[6+len(target):], response)
						sendResponse := func(p []byte) error {
							if pacer != nil {
								pacer.Pace(len(p))
							}
							return send(p)
						}
						if supportsFragments {
							err = wire.SendTunnelDatagram(packet, 4, sendResponse)
						} else {
							err = sendResponse(packet)
						}
						if err != nil {
							if ctx.Err() != nil {
								return
							}
							if !reportedSendError {
								log.Printf("[QUIC-DGRAM] Response send failed for %s: %v", target, err)
								reportedSendError = true
							}
						}
					}
				}()
				defer func() { socket.Close(); <-readerDone }()
				for {
					select {
					case <-flow.ctx.Done():
						return
					case payload := <-flow.queue:
						queuedBytes.Add(-int64(len(payload)))
						_ = socket.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if _, err := socket.Write(payload); err != nil {
							log.Printf("[QUIC-DGRAM] UDP write failed for %s: %v", target, err)
							return
						}
					}
				}
			}(flow, key, target, flowID, supportsFragments)
		}
		if queuedBytes.Add(int64(len(payload))) <= 4*1024*1024 {
			select {
			case flow.queue <- append([]byte(nil), payload...):
				flow.active.Store(time.Now().UnixNano())
			default:
				queuedBytes.Add(-int64(len(payload)))
			}
		} else {
			queuedBytes.Add(-int64(len(payload)))
		}
		mu.Unlock()
	}
}
