//go:build android || (linux && atlanttest)

package atlant

import (
	"atlant.local/protocol/realityauth"
	"atlant.local/protocol/tlsaudit"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestReality3ClientHelloStructuralAudit(t *testing.T) {
	server, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := bytes.Repeat([]byte{6}, 32)
	for _, fp := range []string{"chrome", "firefox", "safari", "edge"} {
		t.Run(fp, func(t *testing.T) {
			var baseline string
			for _, version := range []int{2, 3, 4, 6, 7} {
				client, _ := ecdh.X25519().GenerateKey(rand.Reader)
				pub := client.PublicKey().Bytes()
				legacy, _ := generateSessionIDTokenBound("alice", "0606060606060606060606060606060606060606060606060606060606060606", pub)
				token := legacy
				if version == 3 || version == 4 {
					var err error
					token, err = realityauth.GenerateVersion(version, "alice", key, client, server.PublicKey().Bytes(), time.Now())
					if err != nil {
						t.Fatal(err)
					}
				}
				hello, err := buildClientHelloWithUTLS("example.com", token[:], pub, fp)
				if err != nil {
					t.Fatal(err)
				}
				if version == 6 || version == 7 {
					if err := realityauth.BindHelloVersion(version, hello, "alice", key, client, server.PublicKey().Bytes(), time.Now()); err != nil {
						t.Fatal(err)
					}
					handshake := hello[5:]
					lookup := func([4]byte) []realityauth.Candidate { return []realityauth.Candidate{{Name: "alice", Key: key}} }
					if _, err := realityauth.VerifyHelloVersion(version, handshake[39:71], pub, handshake, server, lookup, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
				summary, err := tlsaudit.Summarize(hello)
				if err != nil {
					t.Fatal(err)
				}
				if summary.SessionIDSize != 32 || len(summary.CipherSuites) == 0 || len(summary.KeyShareGroups) == 0 {
					t.Fatal("unexpected ClientHello structure")
				}
				if version == 2 {
					baseline = summary.StructuralKey()
				} else if summary.StructuralKey() != baseline {
					t.Fatal("wire3 changed structural TLS parameters beyond SessionID random material")
				}
				t.Logf("wire%d: hello=%d bytes, records=%v, SessionID=%d, key_share_groups=%v sizes=%v ALPN=%v", version, summary.HelloSize, summary.RecordSizes, summary.SessionIDSize, summary.KeyShareGroups, summary.KeyShareSizes, summary.ALPN)
			}
		})
	}
}
