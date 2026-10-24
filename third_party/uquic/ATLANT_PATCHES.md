# Pinned browser QUIC dependency

Upstream: https://github.com/refraction-networking/uquic

Commit: `837c7ce1b72bf07b2d29b3dabd5b45c60bec0f42`, 2026-08-04.
Module checksum: `h1:Mishx9fHA/sUb9sFw1d6BsToH21ROmxvlE21w8ccZSU=`.
Original MIT license retained. This is client-only; the listening server still
uses upstream quic-go v0.63.0. Wire4 does not select the browser transport.

Local patch: `internal/handshake/u_crypto_setup.go` checks StoreSession support
through a typed interface rather than calling the removed UQUICConn method.
Unsupported resumption fails explicitly. Atlant wire5 disables session tickets
and does not enable 0-RTT.

The reference is Chrome 146, not automatic Chrome 155 or whole-browser equivalence.
Public Initial bytes and mutual authentication require deployment checks.

Established 1-RTT PTO delegates to the upstream base packer, preserving the
forced PING fallback when no retransmittable data remain. The fork previously
ignored addPingIfEmpty in this branch and aborted active bulk transfers with
"couldn't pack 1-RTT probe packet". Regression: atlant_pto_test.go.

`sys_conn.go` also recognizes an optional `QUICDisableActiveProbing() bool`
policy on the supplied PacketConn. The caller can preserve batch I/O and GSO
while keeping ECN and path-MTU probes disabled, matching its former basic
PacketConn behavior. Native socket capabilities are unchanged without this
explicit policy. This changes neither TLS authentication nor congestion control.
Linux regression: `sys_conn_policy_test.go`.
