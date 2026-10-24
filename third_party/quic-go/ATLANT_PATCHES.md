# Atlant send-only adapter

Based on quic-go v0.63.0; original MIT license and source retained.

`sys_conn.go` recognizes an explicit filtered PacketConn interface. Every read,
deadline, close and received address still belongs to the filtering wrapper.
Only WritePacket borrows the native UDP socket. The wrapper normalizes the
destination and registers outgoing source CIDs, including GSO segments.

The adapter advertises native GSO only, not ECN or DF/path-MTU probing. Existing
quic-go send-side GSO error handling/fallback and pacing remain unchanged.
No SyscallConn is exposed by the admission wrapper. Generic received addresses
continue to bind Retry tokens to IP and port. The native OOB reader is constructed
but never used by the adapter. Stock transports without this interface are unchanged.

`filtered_send_test.go` covers receive isolation, address type, GSO datagram
boundaries/content, registration callback, invalid peers and probe capabilities.
