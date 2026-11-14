package main

import (
	"atlant.local/protocol/quicpeer"
	quic "github.com/quic-go/quic-go"
	"testing"
)

type closingQUICStream struct {
	quicpeer.ClientStream
	readCanceled, writeCanceled bool
	fin                         int
}

func (s *closingQUICStream) CancelRead(quic.StreamErrorCode)  { s.readCanceled = true }
func (s *closingQUICStream) CancelWrite(quic.StreamErrorCode) { s.writeCanceled = true }
func (s *closingQUICStream) Close() error                     { s.fin++; return nil }

func TestQUICCloseUnblocksBothDirections(t *testing.T) {
	s := &closingQUICStream{}
	c := &quicNetStream{ClientStream: s}
	if err := c.CloseWrite(); err != nil || s.fin != 1 || s.readCanceled || s.writeCanceled {
		t.Fatal("half-close canceled response")
	}
	c.Close()
	if !s.readCanceled || !s.writeCanceled {
		t.Fatal("full close leaked stream")
	}
}
