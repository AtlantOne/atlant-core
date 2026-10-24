# Local Android-core regression tests

Normal Android and gomobile builds retain the `android` build constraint.
The explicit Linux-only `atlanttest` constraint enables the same core source
for standalone local tests, without JNI, Android installation or a running TUN.
It does not change the Android production build or the negotiated wire format.

From Windows with Go and the existing Ubuntu WSL distribution:

```powershell
powershell -File scripts/test-android-local.ps1
```

The runner cross-compiles Linux test binaries into `artifacts/tests`, then runs
them in a new network namespace with only loopback and a test UDP echo address.
It never changes Windows/WSL host routes, proxy or physical interfaces. Live
test opt-ins are explicitly cleared. No Linux Go installation is required.

The client QUIC integration test uses the actual Android transport selector,
mutual peer authentication and packet-framed UDP relay. It checks UDP/443 and
an oversized first packet on another UDP port, including 65,507-byte packets,
with TCP fallback disabled. Canceling the relay must not close the pooled QUIC
connection or leave its reader blocked.

The server test uses the production demultiplexer and 0x12 UDP-stream handler,
with QUIC v1 and v2. A 1,200-byte outer QUIC packet deliberately reproduces the
DATAGRAM PMTU limit. The stream still transfers larger packet payloads intact.

Shared framing/cancellation/short-write tests can also run directly:

```powershell
go -C shared test -race ./...
go -C client/android test udp_policy.go udp_policy_test.go
```

This is not an Android VpnService/device test or proof of YouTube playback.
