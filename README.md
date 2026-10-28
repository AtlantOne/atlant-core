# Atlant Core

Atlant brings **TCP and QUIC** into one VPN, with REALITY-style authentication
on both paths. The TCP side offers direct REALITY and XHTTP over REALITY;
the QUIC side connects directly over UDP. You can run the VPN server on an IP
address without registering your own domain or maintaining a public TLS certificate.

If you use VLESS/REALITY and Hysteria, the motivation will be familiar: keep
the convenience of key-based deployment while also having QUIC for concurrent
traffic. Atlant's own **QUIC REALITY** construction puts client admission and
server authentication into the QUIC handshake itself. There is no preliminary
TCP connection or separate HTTPS admission service.

TCP remains available when UDP is unavailable or works poorly. Both paths
share the same server profiles, users and subscriptions, with clients for
Android, Windows and Linux. Choose the transport in the client, or carry TCP
traffic over TCP and UDP traffic over QUIC without adding duplicate servers.

## What Atlant offers

- **A VPN server without your own domain or CA-issued certificate.** Clients
  connect to its IP address and authenticate it using a pinned public key and
  their individual secret. HTTPS for the panel and subscription links is a
  separate concern.
- **REALITY-style authentication on both TCP and QUIC.** Browser TLS profiles
  shape the client handshake; a cryptographic proof distinguishes authorized
  clients from ordinary incoming traffic. QUIC can relay failed admission to
  an operator-configured real HTTP/3 donor.
- **Two transport foundations: TCP and QUIC.** Direct REALITY and HTTP/2-based
  XHTTP are available on the TCP path. Transport choice stays in the client,
  so the same server profile can be used across different networks.
- **Independent streams over QUIC.** Losing data on one stream does not impose
  TCP's connection-wide, in-order delivery wait on every other stream. This is
  especially useful when interactive requests share a connection with downloads.
- **QUIC connects directly.** Authentication travels with the QUIC handshake
  itself, without first establishing a separate TCP connection.
- **An integrated server stack.** SQLite-backed accounts and subscriptions,
  shared subscription quotas across nodes, and an optional separate web panel
  cover deployment as well as tunneling.
- **Native clients and open source.** Android uses a Go AAR; Windows and Linux
  have native cores. The protocol and server can be used without the panel.

## How the connection works

### TCP and XHTTP

The client builds its selected browser TLS profile and binds admission to the
complete ClientHello. The connection authenticates the server against the
pinned key and uses the user's secret to authorize access. TCP carries the
tunnel directly; XHTTP carries it over HTTP/2 inside the REALITY connection.

### Direct QUIC REALITY

The client starts with a QUIC Initial, not a TCP bootstrap. Before TLS hashes
the ClientHello into its transcript, Atlant places an admission proof in the
32-byte Random field. The proof binds the user's secret, static/ephemeral
X25519 exchange and the rest of the ClientHello. Identity and time fields are
masked; the connection ID carries no permanent user tag.

The server reassembles and checks the ClientHello and uses QUIC Retry to
validate the source address. It presents an ephemeral TLS certificate whose
signing key is authenticated using the pinned server key and user secret.
The client does not need a certificate issued for the server's IP or domain.
TLS CertificateVerify and Finished still run, followed by mutual confirmation
bound to the TLS exporter before the tunnel opens.

In other words, “without a certificate” means **without provisioning a public
CA certificate**, not removing TLS authentication or encryption.

See the [handshake walkthrough](docs/protocol/wire7.md) for the implementation
details and [performance notes](docs/protocol/performance.md) for the I/O paths.

## Choosing a transport

| Transport | How it carries traffic | When to choose it |
|---|---|---|
| TCP/REALITY | A protected TCP connection | A straightforward TCP path, including networks where UDP is unavailable |
| XHTTP/REALITY | HTTP/2 inside REALITY | When an HTTP-based tunnel fits your deployment better |
| QUIC REALITY | Direct UDP with multiplexed QUIC streams | Concurrent traffic and interactive use on networks that allow UDP |

QUIC is particularly interesting when bulk transfers and interactive requests
share a connection: independent streams avoid TCP's connection-wide delivery
ordering. TCP provides another path when the network does not suit UDP. The
[performance guide](docs/protocol/performance.md) covers the implementation's
I/O optimizations and measurement methods.

## Repositories

- [Core](https://github.com/AtlantOne/atlant-core): protocol, server and native clients.
- [Android](https://github.com/AtlantOne/atlant-android): Android application.
- [Desktop](https://github.com/AtlantOne/atlant-desktop): Windows graphical client.
- [Panel](https://github.com/AtlantOne/atlant-panel): independent management application.

## Build

Use the Go versions declared in each module's `go.mod`. Run from this directory:

```sh
mkdir -p artifacts/current
go -C server build -trimpath -o ../artifacts/current/atlant-server .
go -C client/linux build -trimpath -o ../../artifacts/current/atlant-linux .
go -C shared build -trimpath -o ../artifacts/current/atlant-cert-agent ./cmd/atlant-cert-agent
```

On Windows:

```powershell
go -C client/windows/core build -trimpath -o ../../../artifacts/current/atlant-win-fixed.exe .
./scripts/build-aar.ps1
```

Windows TUN requires the official Wintun DLL, supplied separately. The Android
library is generated at `artifacts/android/atlant.aar`; copy it into the Android
application repository at the same relative path. Android builds require JDK,
Android SDK/NDK and gomobile.

## Configure

Start with `server_config.example.json` and `atlant_config.example.json`.
Set the server address, SNI/donor settings and keys, then give each user a
separate secret. Clients must pin the server's public key. Keep the management
API on loopback and use an SSH tunnel for remote administration.

Current profiles explicitly select `wire_version: 7`. Update the server and
clients together when changing the wire format.

## Protocol documentation

The [handshake walkthrough](docs/protocol/wire7.md) explains authentication on
both paths. The [threat model](THREAT_MODEL.md) describes the security boundaries,
active probing and client-OS responsibilities. See [SECURITY.md](SECURITY.md)
to report a vulnerability.

## Licensing

Original `server` and `shared` code: Apache-2.0. Original `client` code: MIT.
Local third-party forks retain their own licenses and notices. See `LICENSING.md`,
`NOTICE`, `THIRD_PARTY_NOTICES.md` and the scoped license files.
