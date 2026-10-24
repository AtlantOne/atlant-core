// Package tlsprofiles contains explicitly versioned, independently checked TLS presets.
package tlsprofiles

import u "github.com/refraction-networking/utls"

// Chrome144Spec matches the fresh TCP ClientHello captured from Chrome for
// Testing 144.0.7559.59. Its extension set, groups, key-share sizes, signature
// schemes and ALPN match the existing uTLS 133 implementation. Reuse that
// implementation rather than copying its cryptographic extension generators.
// This describes ClientHello only, not Chrome's HTTP/2 or QUIC behavior.
func Chrome144Spec() (u.ClientHelloSpec, error) { return u.UTLSIdToSpec(u.HelloChrome_133) }
