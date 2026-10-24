package quicaudit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Opt-in public reference corpus, never an interface capture. Source:
// refraction-networking/quic-fingerprint-conformance, multi_chrome_146/input.pcapng.
func TestChromeReferenceCaptureOffline(t *testing.T) {
	path := os.Getenv("ATLANT_CHROME_REFERENCE_PCAP")
	if path == "" {
		t.Skip("set ATLANT_CHROME_REFERENCE_PCAP to a public reference fixture")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	observers := map[string]*Observer{}
	done := map[string]bool{}
	sizes := map[string]int{}
	flights := 0
	firstPackets := 0
	coverage := map[string][][2]int{}
	heads, gaps, tails := map[int]int{}, map[int]int{}, map[int]int{}
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || packet.NetworkLayer() == nil {
			continue
		}
		p := udp.Payload
		if len(p) < 1200 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:5]) != 1 {
			continue
		}
		dcil := int(p[5])
		if dcil < 1 || dcil > 20 || 7+dcil > len(p) {
			continue
		}
		key := packet.NetworkLayer().NetworkFlow().Src().String() + fmt.Sprint(udp.SrcPort) + string(p[6:6+dcil])
		if done[key] {
			continue
		}
		observer := observers[key]
		if observer == nil {
			observer = &Observer{}
			observers[key] = observer
		}
		summary, err := observer.Observe(p)
		if len(observer.summary.DatagramSizes) == 1 {
			var ranges []string
			for i := 0; i < len(observer.seen); i++ {
				if !observer.seen[i] {
					continue
				}
				start := i
				for i < len(observer.seen) && observer.seen[i] {
					i++
				}
				ranges = append(ranges, fmt.Sprintf("%d:%d", start, i))
				coverage[key] = append(coverage[key], [2]int{start, i})
			}
			_ = ranges
		}
		if errors.Is(err, ErrIncomplete) {
			continue
		}
		if err != nil {
			done[key] = true
			continue
		}
		done[key] = true
		resumed := false
		for _, ext := range summary.ClientHello.Extensions {
			if ext == 41 {
				resumed = true
			}
		}
		if resumed || strings.Join(summary.ClientHello.ALPN, ",") != "h3" {
			continue
		}
		flights++
		if firstPackets < 3 {
			t.Logf("cold reference first-datagram coverage=%v hello bytes=%d", coverage[key], summary.ClientHello.HelloSize)
			firstPackets++
		}
		if c := coverage[key]; len(c) == 2 && c[0][0] == 0 {
			heads[c[0][1]]++
			gaps[c[1][0]-c[0][1]]++
			tails[c[1][1]-c[1][0]]++
		}
		sizes[fmt.Sprint(summary.DatagramSizes)]++
	}
	if flights < 3 {
		t.Fatal("not enough cold Chrome flights", flights)
	}
	t.Logf("cold Chrome146 flights=%d; complete-hello datagram-size histogram=%v", flights, sizes)
	t.Logf("first-datagram head-lengths=%v middle-gap-lengths=%v tail-lengths=%v", heads, gaps, tails)
}
