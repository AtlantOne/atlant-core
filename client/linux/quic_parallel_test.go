package main

import (
	"testing"

	"atlant.local/protocol/quicpeer"
	quic "github.com/quic-go/quic-go"
)

type closeOnlyQUICStream struct{ quicpeer.ClientStream }

func (closeOnlyQUICStream) Close() error                     { return nil }
func (closeOnlyQUICStream) CancelRead(quic.StreamErrorCode)  {}
func (closeOnlyQUICStream) CancelWrite(quic.StreamErrorCode) {}

func TestParallelQUICLeasesKeepUDPOnPrimary(t *testing.T) {
	cfg := &Config{WireVersion: 7, QUICParallelConnections: 4}
	var streams []*quicNetStream
	defer func() {
		for _, stream := range streams {
			_ = stream.Close()
		}
	}()
	for i := range quicCarriers {
		lane, release := acquireQUICCarrier(cfg, "tcp")
		streams = append(streams, &quicNetStream{ClientStream: closeOnlyQUICStream{}, release: release})
		if lane != &quicCarriers[i] {
			t.Fatalf("concurrent stream %d did not get its own lane", i)
		}
	}
	lane, release := acquireQUICCarrier(cfg, "udp")
	defer release()
	if lane != &quicCarriers[0] {
		t.Fatal("UDP used a secondary lane")
	}
	_ = streams[2].Close()
	_ = streams[2].Close()
	lane, releaseReplacement := acquireQUICCarrier(cfg, "tcp")
	defer releaseReplacement()
	if lane != &quicCarriers[2] || lane.active != 1 {
		t.Fatal("closing the stream did not return exactly one lease")
	}
}
