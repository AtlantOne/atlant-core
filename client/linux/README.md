# Atlant Linux client

The Linux executable includes the VPN core, a loopback SOCKS5 proxy and a console manager. Existing `-c`, `-config` and other foreground core flags keep working.

## Console menu

```sh
./atlant-linux-amd64 cli
```

Running without arguments opens the same menu when stdin is a terminal. The interface defaults to English.

```text
Atlant — Linux client
1 Connection
2 Servers
3 Subscriptions
4 Settings
5 Journal
6 Help / commands
0 Exit (connection stays running)
```

Servers are grouped by subscription. You can use a list number or a stable profile ID to select a server. The first imported server is selected automatically. Selection and settings are saved; reconnect to apply them to a running connection.

## Typical workflow

```sh
./atlant-linux-amd64 cli profiles add
# Paste an atlant:// link when prompted, not as a shell argument.

./atlant-linux-amd64 cli subscriptions add
# Paste an HTTPS subscription URL when prompted.

./atlant-linux-amd64 cli profiles list
./atlant-linux-amd64 cli profiles select 1
./atlant-linux-amd64 cli settings set tun false
./atlant-linux-amd64 cli connect
./atlant-linux-amd64 cli status
./atlant-linux-amd64 cli logs
./atlant-linux-amd64 cli disconnect
```

`tun false` runs a SOCKS-only client without root. Configure the application to use `127.0.0.1:1080`; the CLI does not overwrite desktop-wide proxy settings or another VPN.

TUN needs root, `/dev/net/tun`, `ip` and `nft`. To avoid managing different catalogs under a normal user and root, use a root-owned state directory consistently:

```sh
sudo ./atlant-linux-amd64 cli --state /var/lib/atlant-client
sudo ./atlant-linux-amd64 cli --state /var/lib/atlant-client status
sudo ./atlant-linux-amd64 cli --state /var/lib/atlant-client disconnect
```

The directory must belong to the user running the CLI and have mode `0700`; state files use `0600`. Do not point it at a shared directory. CLI profile credentials are stored locally in these private files, not encrypted with a desktop keyring. No automatic backups are created.

## Available commands

| Area | Operations |
|---|---|
| Connection | Connect, disconnect, reconnect, actual managed-process status |
| Servers | Import links/base64 lists or native Linux JSON; add, edit, rename, select, delete, share |
| Subscriptions | Multiple independent subscriptions; refresh one/all, rename, delete, share; grouping and selected profile survive key rotation |
| Usage | Subscription upload/download counters, remaining quota bar, expiration |
| Network settings | TUN/SOCKS, MTU, DNS, FakeDNS, IPv6, interface name/address |
| Transport settings | TCP, XHTTP, QUIC, TCP/UDP traffic policy, TLS fingerprint, multiplexing |
| Traffic settings | Padding and background chaffing parameters |
| Diagnostics | TCP endpoint reachability, last 50 log lines, live log following, clear log, log path and logging level |
| Sharing | Atlant links, subscription URLs, terminal QR through the optional `qrencode` utility |

Use `cli help` for command syntax and `cli settings show` for settings. Creating a profile, refreshing a subscription or saving a setting does not ask for confirmation. Deletion, clearing logs and resetting settings do.

`profiles share` and QR output contain credentials. Do not post them publicly. Failed subscription refreshes preserve the old catalog, including on HTTP 503. HTTPS certificate validation is enabled; HTTP is accepted only on an explicit loopback IP for local development.

`ping` measures a TCP connection to the endpoint, not ICMP ping, QUIC connectivity or an authenticated VPN round-trip. `connect` waits for readiness from its own core, not an arbitrary process occupying the SOCKS port. Successful local startup does not by itself verify remote Internet access.

The core runs independently of the menu. Exit leaves it running; `disconnect` sends a graceful termination signal and waits for core-owned network cleanup. The CLI checks process identity and uses a Linux pidfd before signaling. It does not force-kill the core, flush unrelated routes, or reset other VPNs.

## Windows GUI parity

This implements the Linux console management workflow, not full Windows GUI parity. Linux application/domain split routing, desktop-wide proxy integration, a live connection throughput dashboard, UI language/theme selectors and camera/clipboard integrations are not implemented here. The menu deliberately does not expose nonfunctional switches for them. Current routing remains the native Linux client's full-tunnel behavior. QR display requires `qrencode`; it does not scan a camera.

## Build

From this module, with its local shared and third-party dependencies in place:

```sh
go build -trimpath -o atlant-linux .
go test ./...
```

Cross-compilation: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o atlant-linux-amd64 .`; use `GOARCH=arm64` for ARM64.
