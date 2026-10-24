package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSubscriptionCertificate(t *testing.T, host string, lifetime time.Duration) ([]byte, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(lifetime), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k})
}

func TestSubscriptionRenewalBeforeExpiryForIPAndDomain(t *testing.T) {
	now := time.Now()
	for _, life := range []time.Duration{160 * time.Hour, 90 * 24 * time.Hour, 64 * 24 * time.Hour} {
		leaf := &x509.Certificate{NotBefore: now, NotAfter: now.Add(life)}
		if subscriptionRenewalDue(leaf, now.Add(life/2)) {
			t.Fatal("too early")
		}
		if !subscriptionRenewalDue(leaf, now.Add(life*3/4)) {
			t.Fatal("renewal too late")
		}
	}
}

func TestManualSubscriptionCertificateReloadAndTLSIsolation(t *testing.T) {
	cert, key := testSubscriptionCertificate(t, "127.0.0.1", 160*time.Hour)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cp, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, key, 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{options: Config{Mode: "manual", Host: "127.0.0.1", CertFile: cp, KeyFile: kp}}
	if err := m.reload(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, GetCertificate: m.getCertificate, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("HTTPS failed")
	}
	if err := os.WriteFile(kp, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.getCertificate(nil); err != nil {
		t.Fatal("invalid rotation replaced previous valid pair")
	}
	wrongCert, wrongKey := testSubscriptionCertificate(t, "wrong.example", time.Hour)
	if err := m.loadPair(wrongCert, wrongKey); err == nil {
		t.Fatal("wrong hostname accepted")
	}
}
