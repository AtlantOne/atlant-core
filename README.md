# Atlant Core

Experimental VPN engine: server, command-line clients and Android native library.
TCP/REALITY, XHTTP over REALITY and direct QUIC wire7 are implemented here.
Wire7 is an Atlant construction, not wire-compatible with Xray REALITY.
No independent cryptographic audit or browser-indistinguishability claim is made.

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

Start with the example JSON files, not somebody else's private configuration.
Keep the management API on loopback. CA certificates serve panel/subscription
HTTPS, not VPN authentication. Clients must pin the correct server public key.
New profiles should explicitly select `wire_version: 7`.

## Licensing

Original `server` and `shared` code: Apache-2.0. Original `client` code: MIT.
Local third-party forks retain their own licenses and notices. See `LICENSING.md`,
`NOTICE`, `THIRD_PARTY_NOTICES.md` and the scoped license files.
