# Measuring and profiling Atlant

Throughput, loaded latency, loss recovery and traffic resemblance are separate
properties. A loopback result is not an Internet, Android battery or DPI result.

## Native UDP path

Android and Linux pass protected native UDP sockets through
`quicpeer.NativeClientSocket`. It preserves UDP OOB/batch I/O and GSO interfaces.
Opaque legacy admission wrappers are never unwrapped. Android still calls
VpnService.protect before QUIC can use the socket.

The uQUIC fork recognizes the optional `QUICDisableActiveProbing` socket policy.
This retains GSO/batch operations without enabling ECN or path-MTU probing that
the previous basic PacketConn path could not use. It does not turn off QUIC
congestion control or pacing. Windows already passed its native UDP socket;
the Android/Linux policy is not imposed on Windows.
Legacy formats routed through the stock QUIC stack retain their prior basic
socket behavior, because that stack does not implement the optional policy.

The Linux server batches kernel receives (up to 16 datagrams). Each datagram
still crosses the same CID/Initial admission, replay, tuple-bound Retry and
donor-routing logic. Receive batches are not concatenated application packets.
The bounded buffers cost about 1 MiB per server UDP listener, not per user.
Other operating systems and non-native test sockets use single-packet reads.

The server's local quic-go fork has a send-only adapter for wire7 native UDP.
Its receiver remains `basicConn` over `DemuxPacketConn`, including the generic
IP:port Retry address. Only the sender borrows the native socket for OOB/GSO.
Every outgoing source CID still crosses the demux registration callback,
including individual GSO segments. The wrapper exposes no `SyscallConn` and
cannot accidentally become the optimized native receive path. Older wires
and non-native sockets retain their previous path.

The adapter advertises GSO only where the underlying implementation supports
it, not ECN or DF/active MTU probing. Existing quic-go GSO error fallback and
congestion control/pacing remain enabled. It still needs independent review;
local regression tests do not prove immunity to every bypass or DPI classifier.

## TCP and XHTTP application writes

For XHTTP only, REALITY application writers on Android, Linux, Windows and the
server may seal up to four existing TLS records into one socket write. Plain
TCP retains the previous per-record write policy: the broad batching experiment
did not establish a throughput gain and is not enabled for that transport.
Record sizes, sequence
numbers, AEAD, key-usage checks and the existing padding policy are unchanged.
Batching never waits for another application Write: small requests flush
immediately. Storage is private to the connection's existing write lock and
bounded to four full records (with allocator capacity rounding). A failed write
is terminal, including a partial batch. There is no cross-connection lock.

XHTTP passes application chunks up to 64 KiB to its HTTP/2 implementation;
that implementation still enforces negotiated DATA frame sizes. The server
flushes each application chunk, not every manually split 16 KiB fragment.
Partial writes, stalled operations/deadlines and immediate small writes remain
covered by regression tests. The connection pool size and flow-control windows
are not increased blindly.

Identical TLS record bytes do not imply identical TCP packet segmentation or
timing. Socket-write aggregation and GSO may change burst shapes. Do not treat
throughput measurements as proof of browser-equivalent network statistics.

## Diagnostic profiling builds

Only builds made with `-tags atlantprofile` import the local profiling helper.
Normal release binaries do not start it. No HTTP profiling port is opened.

Set `ATLANT_PROFILE_DIR` to an absolute private output directory and optionally
`ATLANT_PROFILE_SECONDS` (1..120, default 8). The helper writes CPU, allocation,
heap, mutex and blocking profiles after the interval. Keep the process alive
until profiles are flushed. Profiles are diagnostic artifacts, not source files
to publish. Profiling runs must not be used as normal throughput measurements.

## Independent connections experiment

`tests/localbench -quic-client-processes 4 -only atlant-quic` starts four client
processes against one server, with a separate QUIC connection in each process.
Four bulk flows are distributed across them. This is diagnostic, not a shipped
connection pool. CPU/RSS includes all four clients; one-flow rows still have
three idle clients. Compare separate result files and retain this metadata.

The default remains one process / one shared connection. More connections are
not adopted automatically: they add state, sockets and observable handshakes.

## UDP counters and buffers

Loopback result rows record `/proc/net/snmp` UDP counter deltas over the full
setup/warmup/sample lifecycle in the isolated namespace. Missing counters are
not represented as zero. RcvbufErrors/SndbufErrors distinguish kernel socket
drops from application byte-count/CRC failures. The report records kernel UDP
buffer limits read-only; it never modifies host sysctls.

`run-impaired.sh` accepts `ATLANT_BENCH_ONLY` to select transports. Use a private
network namespace, fixed bandwidth, RTT/loss and a pipelined workload. Preserve
raw application RTT samples, errors, qdisc drops and all repetitions. Do not run
builds or other throughput tests concurrently with a speed measurement.

## Security and wire checks

Run server replay/wrong-proof/resource tests and the shared QUIC Initial audit
after modifying the socket path. The audit checks IPv4/IPv6, wire6/wire7 and
native/passive socket paths: TLS fields, parameters, CID lengths, empty session
ID, Initial sizes and packet numbers. This guards selected properties; it does
not establish complete indistinguishability from a browser or from its timing.
