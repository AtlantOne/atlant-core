package quicpeer

import "crypto/tls"

// ConfigureTLSPrivacy prevents reusable session tickets from undoing wire3's
// per-connection CID privacy. Peer authentication is still required after TLS.
// Legacy profiles retain their configured resumption behavior.
func ConfigureTLSPrivacy(config *tls.Config, wireVersion int) {
	if wireVersion == 3 || wireVersion == 4 || (wireVersion == 6 || wireVersion == 7) {
		config.SessionTicketsDisabled = true
		config.ClientSessionCache = nil
	}
	if wireVersion == 4 || (wireVersion == 6 || wireVersion == 7) {
		// Match the supported-group order measured from the local Chrome
		// baseline using supported TLS configuration, not packet rewriting.
		// This aligns one field only; Go's entire ClientHello is not Chrome's.
		config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}
	}
}
