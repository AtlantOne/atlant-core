package quicpeer

import (
	utls "github.com/refraction-networking/utls"
	"testing"
)

func TestQUICChromeVersionsDoNotMixExtensions(t *testing.T) {
	for _, name := range []string{"chrome_146", "chrome_156"} {
		spec, err := browserSpec(name, false)
		if err != nil {
			t.Fatal(err)
		}
		anchors, rtt := false, false
		for _, ext := range spec.ClientHelloSpec.Extensions {
			if e, ok := ext.(*utls.GenericExtension); ok && e.Id == 0xca34 {
				anchors = true
				if len(e.Data) != 186 {
					t.Fatal("unexpected trust-anchor payload")
				}
			}
			if e, ok := ext.(*utls.QUICTransportParametersExtension); ok {
				for _, p := range e.TransportParameters {
					if p.ID() == 0x3127 {
						rtt = true
					}
				}
			}
		}
		if anchors != (name == "chrome_156") || rtt != (name == "chrome_146") {
			t.Fatalf("mixed QUIC version %s: anchors=%v rtt=%v", name, anchors, rtt)
		}
	}
	if _, err := browserSpec("chrome_999", false); err == nil {
		t.Fatal("unknown QUIC profile accepted")
	}
	for i := 0; i < 20; i++ {
		if _, err := browserSpec("random_chrome", false); err != nil {
			t.Fatal(err)
		}
	}
}
