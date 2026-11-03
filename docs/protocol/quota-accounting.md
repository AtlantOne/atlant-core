# Shared subscription traffic accounting

A coordinator reserves byte credit for each node/session in SQLite. The initial reservation is 4 MiB. Busy nodes prefetch additional credit based on measured traffic and coordinator latency; outstanding credit is bounded to 64 MiB per grant. These are accounting reservations between trusted servers, not client authentication tickets or identifiers in VPN packets.

A reply with `can_top_up: true` supports extending the existing grant. A request containing the current `grant`, cumulative `up`/`down`, `close: false` and a positive `want` reports usage and requests additional credit atomically. The grant ID stays unchanged. Its `capacity` is cumulative and can exceed 64 MiB over its lifetime; `capacity - up - down` is the outstanding balance that is bounded. The total across all nodes remains limited by the subscription balance.

Top-ups run outside the packet path. While one is pending, other flows can spend already confirmed bytes. A lost reply does not make new credit spendable: the same request ID is retried, and allocation-changing replies are retained for idempotent recovery. Usage incurred during the RPC remains in the node's cumulative counters. Closing a grant is reserved for settlement and explicit lifecycle changes; no credit may be spent while its return is ambiguous.

When all confirmed credit has been consumed, transmission still needs a successful refill. The implementation does not invent credit when the coordinator is unavailable. Expiry, explicit revocation and the global traffic limit continue to apply. Worker shutdown cancels and joins pending prefetch operations before final settlement.

New nodes recognize older coordinators by the absence of `can_top_up` and retain the previous close-and-reallocate behavior with them. Coordinators preserve compatibility with older nodes that request only 4 MiB and do not send top-up requests. Upgrade both sides to obtain the non-closing refill behavior.

# Client transport policy

In split mode, UDP DNS follows the selected UDP carrier. Selecting QUIC for UDP does not send DNS through the TCP data carrier. Explicit direct DNS and FakeDNS policies retain their own behavior. Healthy TCP/Yamux sessions are reused until disconnect, a profile/network change, or a transport failure; their age alone does not close live streams.
