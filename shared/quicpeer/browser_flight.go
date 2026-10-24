package quicpeer

import (
	"crypto/rand"
	"errors"
	"io"

	browser "github.com/refraction-networking/uquic"
)

// The public Chrome146 corpus's common cold flight has two 1250-byte UDP
// datagrams. The first carries a short head and the tail, not a sequential
// prefix. The sampled ranges below follow observed bounds, not a claim of
// reproducing the full browser's joint statistical distribution.
type chromeColdFlight struct{ head, gap int }

func (f chromeColdFlight) Build(data []byte) ([]byte, error) {
	return (browser.QUICFrames{browser.QUICFrameCrypto{Offset: 0, Length: 0}}).Build(data)
}

func (f chromeColdFlight) BuildFlight(data []byte, budgets []browser.InitialDatagramBudget) ([][]byte, error) {
	if len(budgets) != 2 {
		return nil, errors.New("Chrome cold flight requires two datagram budgets")
	}
	// Long SNI/ECH can change Hello length. Keep both packets within their
	// actual header/Retry-token budgets instead of oversizing a UDP packet.
	gap := max(f.gap, len(data)-(budgets[0].MaxFrameBytes-140))
	if gap > budgets[1].MaxFrameBytes-140 || f.head+gap >= len(data) {
		return nil, errors.New("Chrome cold ClientHello exceeds packet budgets")
	}
	plan := browser.QUICRandomFlightFrames{PerDatagram: []browser.QUICRandomFlightDatagram{
		{CryptoRanges: []browser.QUICCryptoRange{{Offset: 0, Length: f.head}, {Offset: f.head + gap}}, Frames: browser.QUICRandomFrames{MinCRYPTO: 3, MaxCRYPTO: 8, MinPING: 1, MaxPING: 4, MinPADDING: 2, MaxPADDING: 6, Length: 1050}},
		{CryptoRanges: []browser.QUICCryptoRange{{Offset: f.head, Length: gap}}, Frames: browser.QUICRandomFrames{MinCRYPTO: 6, MaxCRYPTO: 14, MinPING: 1, MaxPING: 4, MinPADDING: 2, MaxPADDING: 6, Length: 1050}},
	}}
	return plan.BuildFlight(data, budgets)
}

func configureChromeFlight(spec *browser.QUICSpec, ipv6 bool) error {
	var draw [3]byte
	if _, err := io.ReadFull(rand.Reader, draw[:]); err != nil {
		return err
	}
	size := 1250
	if ipv6 {
		size = 1230
	}
	spec.InitialPacketSpec.InitialPackets = []browser.InitialPacketPlan{{PacketSize: size}, {PacketSize: size}}
	spec.InitialPacketSpec.FrameBuilder = chromeColdFlight{head: 55 + int(draw[0])%30, gap: 847 + int(draw[1])%69}
	return nil
}
