package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Local fake ACME CA exercises real acme.Client JWS/order/HTTP-01/CSR/PEM
// workflow. No request to Let's Encrypt or other external host is performed.
func TestSubscriptionACMEIssueRenewAndPersistIPAndDomain(t *testing.T) {
	for _, test := range []struct {
		mode   string
		broker bool
	}{{"acme-ip", false}, {"acme-domain", false}, {"acme-ip", true}, {"acme-domain", true}} {
		mode := test.mode
		t.Run(fmt.Sprintf("%s/broker=%t", mode, test.broker), func(t *testing.T) {
			host := "vpn.example.test"
			if mode == "acme-ip" {
				host = "198.51.100.20"
			}
			manager := &Manager{options: Config{Mode: mode, Host: host, CacheDir: t.TempDir(), AcceptTerms: true}, challenges: make(map[string]string)}
			var handler http.Handler = http.HandlerFunc(manager.challengeHandler)
			if test.broker {
				manager.options.ChallengeDir = t.TempDir()
				handler = ChallengeBroker(manager.options.ChallengeDir)
			}
			challengeServer := httptest.NewServer(handler)
			defer challengeServer.Close()
			issuer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			var mu sync.Mutex
			var base string
			var certificate []byte
			var orderCount, nonce int
			authorized := false
			caServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				nonce++
				w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprint(nonce))))
				w.Header().Set("Content-Type", "application/json")
				payload := func() map[string]json.RawMessage {
					var jws struct {
						Payload string `json:"payload"`
					}
					_ = json.NewDecoder(r.Body).Decode(&jws)
					data, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
					var value map[string]json.RawMessage
					_ = json.Unmarshal(data, &value)
					return value
				}
				order := func(status string) map[string]any {
					return map[string]any{"status": status, "identifiers": []map[string]string{{"type": map[bool]string{true: "ip", false: "dns"}[mode == "acme-ip"], "value": host}}, "authorizations": []string{base + "/auth"}, "finalize": base + "/finalize", "certificate": base + "/cert"}
				}
				switch r.URL.Path {
				case "/directory":
					json.NewEncoder(w).Encode(map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order", "meta": map[string]any{"profiles": map[string]string{"shortlived": "https://example.test/profile"}}})
				case "/nonce":
					w.WriteHeader(200)
				case "/account":
					w.Header().Set("Location", base+"/account/1")
					w.WriteHeader(201)
					io.WriteString(w, `{"status":"valid"}`)
				case "/new-order":
					p := payload()
					var profile string
					json.Unmarshal(p["profile"], &profile)
					if mode == "acme-ip" && profile != "shortlived" {
						t.Error("IP requested without shortlived profile")
					}
					if mode == "acme-domain" && profile != "" {
						t.Error("ordinary domain profile overridden")
					}
					orderCount++
					authorized = false
					w.Header().Set("Location", base+"/order")
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(order("pending"))
				case "/auth":
					state := "pending"
					if authorized {
						state = "valid"
					}
					json.NewEncoder(w).Encode(map[string]any{"status": state, "identifier": map[string]string{"type": map[bool]string{true: "ip", false: "dns"}[mode == "acme-ip"], "value": host}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge", "token": "test-token"}}})
				case "/challenge":
					req, _ := http.NewRequest(http.MethodGet, challengeServer.URL+"/.well-known/acme-challenge/test-token", nil)
					req.Host = host
					response, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					data, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if response.StatusCode != 200 || len(data) == 0 {
						t.Error("HTTP-01 response unavailable")
						w.WriteHeader(500)
						return
					}
					authorized = true
					io.WriteString(w, `{"status":"valid","type":"http-01","token":"test-token"}`)
				case "/order":
					json.NewEncoder(w).Encode(order("ready"))
				case "/finalize":
					p := payload()
					var csr64 string
					json.Unmarshal(p["csr"], &csr64)
					der, _ := base64.RawURLEncoding.DecodeString(csr64)
					csr, err := x509.ParseCertificateRequest(der)
					if err != nil || csr.CheckSignature() != nil {
						t.Error("invalid CSR")
						w.WriteHeader(400)
						return
					}
					life := 90 * 24 * time.Hour
					if mode == "acme-ip" {
						life = 160 * time.Hour
					}
					leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(orderCount + 1)), DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
					der, err = x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, issuer)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
					json.NewEncoder(w).Encode(order("valid"))
				case "/cert":
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					w.Write(certificate)
				default:
					http.NotFound(w, r)
				}
			}))
			defer caServer.Close()
			base = caServer.URL
			manager.directoryURL = base + "/directory"
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i := 0; i < 2; i++ {
				if err := manager.issue(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if orderCount != 2 {
				t.Fatal("renewal did not issue another certificate")
			}
			if manager.certificate == nil || manager.certificate.Leaf.VerifyHostname(host) != nil {
				t.Fatal("issued identity mismatch")
			}
			if ip := net.ParseIP(host); ip != nil && len(manager.certificate.Leaf.IPAddresses) != 1 {
				t.Fatal("missing IP SAN")
			}
			copy := &Manager{options: manager.options}
			copy.directoryURL = manager.directoryURL
			if err := copy.reload(); err != nil {
				t.Fatal("restart could not load bundle", err)
			}
			copy.directoryURL = "https://another-ca.invalid/directory"
			if err := copy.reload(); err == nil {
				t.Fatal("certificate cache reused across different CA profiles")
			}
			if info, err := os.Stat(filepath.Join(manager.options.CacheDir, "subscription.pem")); err != nil || info.Size() == 0 {
				t.Fatal("bundle not persisted")
			}
		})
	}
}
