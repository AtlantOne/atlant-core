# Chrome 144 reference

`chrome144.json` was measured on loopback from an unmodified Google Chrome for
Testing 144.0.7559.59 Windows headless shell on 2026-10-23. The TLS peer was
`localhost`; a new temporary browser profile was used. No external TLS server
or real browser profile was accessed. Only structural fields are retained;
randoms, public key-share bytes and the session ID are not distributed.

Official binary metadata:
https://googlechromelabs.github.io/chrome-for-testing/144.0.7559.59.json

Reproduce with `scripts/capture-chrome-hello.py` and the
`shared/cmd/tls-hello-summary` tool. Tests compare cipher order, extensions,
groups, key-share sizes, signatures and ALPN. Extension ordering, GREASE and
ECH lengths are randomized and are not fixed byte-for-byte identities.
This reference is for a fresh TCP handshake, not resumed TLS, Android Chrome,
HTTP/2, QUIC, or a guarantee of undetectability.
