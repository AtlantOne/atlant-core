# DNS policy for IPv4-only egress

`dns_ipv4_only` is a server JSON setting, disabled by default. Set it explicitly
to `true` only for deployments where clients must use IPv4 discovery because
the server has no working IPv6 egress. Restart the server to apply configuration.
It is compatible with existing 2.x clients and does not change peer auth, CID,
TLS, stream framing, padding, chaffing or firewall rules.

On replies from an upstream DNS destination at port 53, successful AAAA, SVCB
(64) and HTTPS (65) answers become synthetic NOERROR/NODATA replies preserving
transaction ID and question. A replies are untouched byte-for-byte. Error
responses and malformed input are not rewritten. SVCB/HTTPS discovery is
suppressed to avoid advertising unusable IPv6 hints; this also removes their
other service metadata and may affect protocols relying on that metadata.
Ordinary HTTP Alt-Svc negotiation is not modified by this DNS policy.

The policy applies to UDP inside REALITY, XHTTP, QUIC streams and QUIC
DATAGRAMs, and also to ordinary DNS-over-TCP passing through these transports.
TCP framing, partial reads, socket close and deadlines are retained.

## Boundaries

- This does not create an IPv6 route, enable NAT64, translate IPv6 literals,
  or recover a destination domain from an IP. Existing cached AAAA addresses
  and explicit IPv6 destinations can still fail. Reconnect clients/restart
  applications to discard stale flows; application caches may persist longer.
- DoH/DoT/DoQ and applications' own DNS resolvers are not intercepted. The
  setting is not a comprehensive IPv6 deny policy or a leak-prevention feature.
- Synthetic replies clear AD/AA/TC and contain no forged DNSSEC proof. They
  are not cryptographically authenticated denial of existence. A validating
  client can reject them; keep the policy disabled for workloads requiring
  end-to-end DNSSEC validation or arrange real IPv6 egress instead.
- The policy must not be presented as fixing every DNS failure or proving
  phone playback stability. Authentication failures, timeouts before reaching
  the server and failure to return replies to a phone need separate diagnosis.
- No VLESS/Xray profiles or limits are changed by this Atlant setting.

## Verification and rollback

`go -C server test -race ./...`, `go -C server vet ./...` and the DNS-policy fuzz
target cover the transformation and TCP framing. The isolated network runner
also exercises production QUIC v1/v2 UDP-stream and DATAGRAM relay paths.

Live Android-core probes are opt-in (`ATLANT_TEST_CONFIG`,
`ATLANT_EXPECT_IPV4_DNS=1`, `TestLiveDNSIPv4Policy`); no real TUN/JNI is involved.
`tests/live_dns_policy.py` additionally checks DNS-over-TCP via the Windows
SOCKS clients and real WAN path with `ATLANT_RUN_LIVE=1`.

Keep the old binary, configuration, keys and users file before installation.
`scripts/vds-maintenance.py install-ipv4-dns` is deliberately restricted to the
known `/root/atlant_server` + `/root/config.json` deployment with no IPv6
default route. It arms a five-minute systemd rollback timer before mutation,
restoring both binary and config unless committed after successful checks.
The manual rollback command can also restore a committed candidate, provided
the running binary still matches that candidate (not a newer deployment).
