module atlant-server

go 1.27.2

replace github.com/refraction-networking/utls => ../third_party/utls

replace github.com/refraction-networking/uquic => ../third_party/uquic

replace github.com/quic-go/quic-go => ../third_party/quic-go

require (
	atlant.local/protocol v0.0.0
	github.com/gofrs/flock v0.13.0
	github.com/hashicorp/yamux v0.1.2
	github.com/quic-go/quic-go v0.63.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.60.0
	modernc.org/sqlite v1.60.1
)

replace atlant.local/protocol => ../shared

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	github.com/refraction-networking/uquic v0.0.7-0.20260804184259-837c7ce1b72b // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	modernc.org/libc v1.77.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
