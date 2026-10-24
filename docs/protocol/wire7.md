# Wire7: overview

This is an implementation overview, not a complete formal security proof or
an interoperability specification for third-party implementations.

The profile pins a static X25519 server public key and contains an individual
user PSK. TCP/XHTTP use the Atlant REALITY-like path with version-specific
full-ClientHello admission. XHTTP runs HTTP/2 inside that protected connection.

QUIC has no preliminary TCP connection, ticket issuer or separate HTTPS
admission service. An opt-in uTLS hook binds the finalized ClientHello before
transcript hashing. Only its 32-byte Random is changed: masked tag/time,
fresh nonce and a 128-bit PSK/static-DH proof. QUIC legacy_session_id is empty.

The server bounds and reassembles Initial CRYPTO data before admission.
Retry validates the source tuple; an unauthenticated captured flight does not
commit replay state. Valid client admission leads to an ephemeral TLS leaf
whose signing key is authenticated by a static-DH/PSK proof before the client
reveals its user name. TLS CertificateVerify/Finished remain in use. After TLS,
both peers complete exporter-bound PSK confirmation before opening the tunnel.

Invalid admission may relay to an operator-fixed genuine QUIC/H3 donor.
It does not select an arbitrary donor from client SNI. TLS certificates remain
internal messages of QUIC/TLS; “no external CA required” does not mean the TLS
Certificate message is absent.

Relevant implementations: `shared/quicreality`, `shared/quicpeer`,
`shared/realityauth`, `server/quic_direct.go`, and the two patched dependencies.
Read the root threat model before making public security claims.

Socket-path performance work and its limits are described in
[performance.md](performance.md). These changes do not introduce a new wire
version or bypass the server's admission reader.
