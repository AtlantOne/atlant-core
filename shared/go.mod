module atlant.local/protocol

go 1.27.2

replace github.com/refraction-networking/utls => ../third_party/utls

replace github.com/refraction-networking/uquic => ../third_party/uquic

require (
	github.com/gofrs/flock v0.13.0
	github.com/google/gopacket v1.1.19
	github.com/quic-go/quic-go v0.63.0
	github.com/refraction-networking/uquic v0.0.7-0.20260804184259-837c7ce1b72b
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	golang.org/x/text v0.43.0 // indirect
)
