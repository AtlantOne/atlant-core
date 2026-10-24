# QUIC admission: opt-in REALITY 3.x candidate

Status, 2026-10-18: integrated in the local server and Android/Windows/Linux
candidate when explicitly selecting wire version 3. Default/unversioned
profiles retain 2.x; the live VDS is not switched by this source change.
Bootstrap is ONLY inside mutually authenticated REALITY 3.x, never HTTPS.
See [REALITY3_SPEC.md](../../REALITY3_SPEC.md) for the paired implementation,
one-attempt batch lifecycle, fail-closed restart and exact limits.
This is not an independently audited protocol, HTTP/3 implementation or
evidence of indistinguishability from browser traffic.

## Why this candidate exists

The legacy client CID contains a stable user tag recoverable using only public
bytes. Changing its public mask cannot fix that. This candidate instead puts
20 CSPRNG bytes in a client-issued CID, without encoding a subject, timestamp,
counter, version marker or common client secret. A server-side SHA-256 index
maps each issued value to its owner privately. No new cipher is introduced.

This removes the *encoded stable tag from this candidate's token construction*;
it does not eliminate correlation by server IP, packet timing, lengths, TLS
parameters, CID reuse, traffic patterns or endpoint behavior. A constant
20-byte CID length may itself contribute to a fingerprint. Randomness alone
does not establish browser equivalence. QUIC Initial encryption is not a
privacy boundary against an observer who knows the public Initial keys.

The privacy requirement for issued CIDs is described in
[RFC 9000, section 5.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1):
externally recoverable information must not correlate different CIDs belonging
to one connection. This reference motivates the review; it does not certify
the candidate or establish its full compliance with QUIC.

The candidate trades stateless admission for finite state and authenticated
replenishment. It is not yet a final choice of v3 admission architecture.

## Byte format and admission state

Token: exactly 20 opaque random bytes (`crypto/rand`), no fields. Server lookup:
`SHA256(token)` -> private owner, expiry, state and attempt binding. Bearer
admission material must not appear in logs, metrics labels or public reports.
`String()` redacts ordinary formatting only; raw bytes and explicit formatters
can still expose it. This is not a secret-erasure guarantee in Go memory.

States: `issued -> claimed(attempt) -> spent`. A duplicate Initial belonging to
the same pending attempt may be admitted again. A different attempt is rejected.
Commit requires successful TLS-exporter-bound mutual peer authentication AND
the same private owner. Wrong authenticated owners and failed attempts burn
their token. Spent entries remain until expiry (or explicit administrative
revocation), counting against the quota; they cannot admit another handshake.

Admit NEVER authorizes proxy traffic. The token is visible on the network:
anyone who observes it can race or replay it, potentially causing denial of
service. They still must not gain access without the existing peer proof.
This primitive does not provide address validation or anti-amplification.

## Limits and fast path

- Defaults: 65,536 entries total, 256 per subject, TTL 15 minutes.
- Configurable hard bounds: 1..1,048,576 entries, 1..capacity per subject,
  TTL 1 second..1 hour; batch size 1..256; subject name 1..256 bytes.
- Spent and expired-not-yet-pruned entries count towards memory occupancy.
  Hash-map/heap capacity can retain their bounded high-water allocation.
- Unknown input: one fixed-size hash and map lookup under a mutex, no user
  enumeration, session allocation or full expired-entry sweep. A global mutex
  is NOT a guarantee against CPU/lock contention under a flood.
- Known expired lookup: delete that entry and its heap record. Authenticated
  issuance prunes all expired entries; this can take O(capacity log capacity).
- Revocation: administrative O(capacity) scan, also removes heap records.
  Revocation/issuance cycles cannot accumulate an unbounded stale heap.
- Entropy failure, collision or quota failure: no partial batch insertion.
  Full stores reject issuance rather than evict valid or spent entries.

`CIDPool` is finite and connection-local, copies its input, rejects duplicate
values and consumes each exactly once under a mutex. Exhaustion is an error:
there is no implicit fallback to legacy or unregistered random CIDs. Reusing
the same batch in another pool is forbidden by the integration contract, not
prevented by an in-memory pool. The server can reject reuse but cannot undo
the passive linking of an already repeated CID.

## Original integration checklist (historical; see current spec above)

The following checklist records the original primitive contract. The local
candidate now implements bootstrap/attempt association and uses fresh RAM-only
batches instead of persistent token snapshots. Server defaults are overridden
to TTL 90 seconds / 1024 slots per user. Public release, independent review,
WAN/device validation and dependency-hook revalidation remain separate gates.

1. Independently authenticate/authorize bootstrap and replenishment. Never
   expose Issue as a public unauthenticated endpoint. Decide the bootstrap
   trust anchor, revocation, availability, rate limits and fingerprint.
   Expiring batches cannot be a permanent static offline profile.
2. Implement durable client consumption **before first wire use**, including
   crash/reinstall/backup restoration, parallel transports, CID rotation and
   batch exhaustion. Never retry a previously exposed token on a new attempt.
3. Define durable server recovery or explicit fail-closed rebootstrap. The
   current Store is RAM-only: on restart all old tokens become unknown. It
   does not persist replay history, issuance state or tombstones. No automatic
   loading of historical unspent snapshots is safe without a lifecycle design.
4. Parse client SCID in Initial safely; quic-go's client CID generator does
   not set the original destination CID. Define a server-side Attempt binding
   to the peer and original handshake, with unambiguous encoding and handling
   for QUIC v1/v2, Retry, retransmissions and address changes. Never accept a
   client-chosen arbitrary Attempt as proof that packets share a connection.
   The current package deliberately does not implement this association.
5. Route established CIDs before new admission; atomically associate a claim
   with exactly one QUIC connection. Resolve the transition between pending
   handshake, spent token and registered live routing; do not reject legitimate
   retransmissions or create two sessions. Auth failure/timeout must Retire.
6. Perform the existing TLS-bound peer proof, check the resulting identity
   against admission via Commit, and only then enable application traffic.
   CID rotation cannot bypass any of these checks.
7. Retain QUIC anti-amplification, validate malformed/version-negotiation input,
   and define identical externally safe handling for unknown/expired/spent
   input. Bound decoy forwarding, connection counts, handshake time and work
   per source as well as per authenticated subject. The primitive alone
   does NOT implement a decoy or transport resource limits.
8. Use explicitly separate new/legacy profiles and paired client/server
   migration. Test old/old, new/new, old/new, new/old and no hidden downgrade.
   Do not auto-convert existing 2.x configuration or overwrite rollback builds.

## Validation and limits of evidence

From the repository root:

```powershell
go -C shared test -race ./...
go -C shared vet ./...
go -C shared test ./quicadmission -run '^$' -bench BenchmarkUnknownAdmission -benchmem
go -C shared test ./quicadmission -run '^$' -fuzz FuzzParseToken -fuzztime 5s
go -C shared test ./quicadmission -run '^$' -fuzz FuzzAdmissionStateMachine -fuzztime 5s
```

Tests cover state transitions, retransmission, competing attempts, wrong
owners, atomic issuance, entropy failure/collisions, quotas, expiry, revocation,
restart fail-closed, unknown-input allocations and concurrent pool consumption.
These are local primitive tests, NOT a production v3 handshake/migration,
network active-probing assessment, proof of cryptographic security, real-phone
roaming test or measurement of censor detection rates.

Before claiming improved censorship resistance, separately capture and compare
Initial/ClientHello fingerprints, transport parameters, ACK/Retry/version
behavior, invalid-client responses and burst/timing/length distributions for
each actual client platform and transport. Test TCP/REALITY and XHTTP too;
passing a QUIC-only test says nothing about their signatures. Publish concrete
criteria and traces with secrets removed, not an invented overall score.
