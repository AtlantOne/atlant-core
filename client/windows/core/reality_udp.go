package main

import (
	"atlant.local/protocol/quicpeer"

	quic "github.com/quic-go/quic-go"
)

// RealityConnIDGenerator delegates to the shared unique 20-byte CID format.
// The TLS-bound authentication handshake must also succeed before payloads.
type RealityConnIDGenerator struct{ generator *quicpeer.CIDGenerator }

func NewRealityConnIDGenerator(user string, key []byte) *RealityConnIDGenerator {
	return &RealityConnIDGenerator{generator: quicpeer.NewCIDGenerator(user, key)}
}

func (g *RealityConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	return g.generator.GenerateConnectionID()
}
func (g *RealityConnIDGenerator) ConnectionIDLen() int { return g.generator.ConnectionIDLen() }
