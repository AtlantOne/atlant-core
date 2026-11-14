package quicpeer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	browser "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"math/big"
	"strings"
)

// Public Chrome root-store IDs captured from a fresh Chrome 156 profile.
// These describe trust-anchor preferences, not credentials or local roots.
const chrome156TrustAnchors = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df13021408839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d679090804d679090a04d679090b04d679090c04d679090d04d679090f"

func configureChrome156Hello(spec *browser.QUICSpec) {
	for _, ext := range spec.ClientHelloSpec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			filtered := make(utls.TransportParameters, 0, len(qtp.TransportParameters))
			for _, param := range qtp.TransportParameters {
				// Chrome 156 no longer advertises google_initial_rtt.
				if param.ID() != 0x3127 {
					filtered = append(filtered, param)
				}
			}
			qtp.TransportParameters = filtered
		}
	}
	anchors, err := hex.DecodeString(chrome156TrustAnchors)
	if err != nil {
		panic("invalid built-in Chrome trust-anchor IDs")
	}
	spec.ClientHelloSpec.Extensions = append(spec.ClientHelloSpec.Extensions, &utls.GenericExtension{Id: 0xca34, Data: anchors})
	spec.ClientHelloSpec.Extensions = utls.ShuffleChromeTLSExtensions(spec.ClientHelloSpec.Extensions)
}

func browserSpec(name string, ipv6 bool) (browser.QUICSpec, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == "chrome" || name == "chrome_auto" {
		name = "chrome_156"
	}
	if name == "random_chrome" || name == "random" {
		n, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			return browser.QUICSpec{}, err
		}
		name = []string{"chrome_146", "chrome_156"}[n.Int64()]
	}
	if name != "chrome_146" && name != "chrome_156" {
		return browser.QUICSpec{}, fmt.Errorf("unsupported QUIC browser profile %q", name)
	}
	id := browser.QUICChrome_146_IPv4
	if ipv6 {
		id = browser.QUICChrome_146_IPv6
	}
	spec, err := browser.QUICID2Spec(id)
	if err != nil {
		return spec, err
	}
	if name == "chrome_156" {
		configureChrome156Hello(&spec)
	}
	if err := configureChromeFlight(&spec, ipv6); err != nil {
		return spec, err
	}
	return spec, nil
}
