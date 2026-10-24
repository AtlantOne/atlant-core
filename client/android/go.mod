module atlant-android

go 1.27.2

replace github.com/refraction-networking/utls => ../../third_party/utls

replace github.com/refraction-networking/uquic => ../../third_party/uquic

require (
	atlant.local/protocol v0.0.0
	github.com/hashicorp/yamux v0.1.2
	github.com/quic-go/quic-go v0.63.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.60.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
	gvisor.dev/gvisor v0.0.0-20261008104908-5133cf662349
)

replace atlant.local/protocol => ../../shared

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	github.com/refraction-networking/uquic v0.0.7-0.20260804184259-837c7ce1b72b // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

tool golang.org/x/mobile/cmd/gobind
