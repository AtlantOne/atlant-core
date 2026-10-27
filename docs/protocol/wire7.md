# Inside Atlant: TCP, XHTTP and direct QUIC REALITY

Atlant combines three transports with key-based server authentication. A client
profile contains the server address, pinned static X25519 public key and an
individual user secret (PSK). Running the VPN does not require registering a
domain or obtaining a certificate from a public CA.

This document walks through the current wire format, selected in configuration
as `wire_version: 7`.

## TCP and XHTTP

Both transports start through Atlant's REALITY path. The client builds the
selected browser TLS profile, and admission is bound to the complete ClientHello.
That binding prevents changing other Hello fields while retaining the same
admission proof. The server key is pinned in the profile rather than trusted
through the public CA system.

TCP carries the tunnel directly. XHTTP runs HTTP/2 inside the protected
connection, giving Atlant an HTTP-based transport alongside its TCP and QUIC
paths. All three use the same account and subscription system.

## Why QUIC has its own handshake

A TCP bootstrap in front of QUIC adds another connection and makes UDP depend
on a successful TCP exchange. Ticket-based admission adds issuance, refresh
and token-pool state. Atlant instead carries admission in the first QUIC
handshake: the connection begins over UDP and stays on QUIC.

QUIC also provides independent streams. A missing packet can delay a stream
whose data it carries without imposing TCP's connection-wide delivery ordering
on all the others. Congestion control still applies to the whole connection;
independent streams do not make bandwidth or packet loss free.

## Direct QUIC REALITY, step by step

### 1. Build and bind the ClientHello

The client builds its browser-profile ClientHello. An opt-in uTLS hook runs
after the Hello is finalized but before TLS transcript hashing. Atlant changes
only the 32-byte Random field; the QUIC `legacy_session_id` stays empty.

The Random contains masked identity/time fields, a fresh nonce and a 128-bit
admission proof. The proof combines the user's PSK, a shared value from the
client's ephemeral X25519 key and pinned server key, and a hash of the rest of
the ClientHello. Changing a bound field invalidates admission. The QUIC
connection ID contains no permanent user tag and is not an access credential.

### 2. Validate admission and source address

The server reassembles Initial CRYPTO data within bounded buffers before
checking admission. QUIC Retry validates the source IP/port tuple. Simply
presenting a captured Hello does not consume its owner's admission: replay
state is committed only after the authenticated exchange succeeds.

### 3. Authenticate the server inside TLS

An admitted client receives an ephemeral TLS leaf certificate. Its signing key
is authenticated by a proof derived from static DH and the user PSK, before
the client reveals its user name. This replaces the need to provision a
CA-issued certificate for the VPN endpoint; TLS CertificateVerify and Finished
remain part of the handshake.

The certificate is therefore still a TLS message. It is the certificate
*infrastructure* — domain ownership, CA issuance and renewal for the VPN —
that this design removes from deployment.

### 4. Confirm both peers and open the tunnel

After TLS, both peers complete PSK confirmation bound to the TLS exporter.
That ties authorization to this particular TLS connection. Capturing a CID
or replaying public handshake bytes does not supply the secret needed to
complete the exchange and open the tunnel.

### 5. Handle traffic without valid admission

Failed admission can be relayed to a genuine QUIC/HTTP/3 donor selected by the
operator. The server does not take an arbitrary donor destination from a
visitor's SNI. Browser profiles and donor routing are the traffic-masking
parts of the design; key pinning and mutual proofs provide authentication.

## Deployment and implementation

The VPN endpoint can be an IP address. HTTPS certificates for the optional
management panel and subscription delivery are configured separately and do
not participate in VPN authentication.

The main implementation lives in `shared/quicreality`, `shared/quicpeer`,
`shared/realityauth` and `server/quic_direct.go`, with TLS/QUIC hooks in the
local dependency forks. [Performance notes](performance.md) describe native
UDP batching, GSO and TCP/XHTTP write paths.

## Security boundaries

The construction has not yet had an independent cryptographic audit. Browser
TLS profiles do not establish that an entire QUIC connection has browser-identical
packet sizes, timing or probe responses. Historical admission metadata also
has different key-compromise properties from tunnel payload encryption.
The [threat model](../../THREAT_MODEL.md) records these boundaries, replay/probing
cases and client-OS responsibilities in detail.
