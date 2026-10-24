# Local uTLS changes

Base: github.com/refraction-networking/utls v1.8.2. Upstream LICENSE retained.

Atlant wire7 uses an opt-in UQUICConn.SetClientHelloHook. The callback executes
after final ClientHello serialization and before TLS transcript hashing. It can
change only Random, requires the actual X25519 keyshare private key, and checks
that reserialization did not change any other byte. Errors fail the handshake.
No hook is installed for existing wire2/3/4/6 traffic. No TLS transcript checks,
CertificateVerify or Finished validation are disabled by this patch.

Rebase and run direct-QUIC identity, replay, negative-hook and legacy regressions
when updating this dependency; do not replace the fork without preserving them.
