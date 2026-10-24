package quicreality

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// Certificate is a per-handshake TLS object, not a CA-issued deployment
// certificate. Its public key is authenticated by the pinned-static-DH/PSK
// proof, then TLS CertificateVerify proves possession of the signing key.
func Certificate(sni string, a Admission) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: sni}, DNSNames: []string{sni}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SubjectKeyId: mac(a.PeerKey[:], "certificate-key", spki)}
	if ip := net.ParseIP(sni); ip != nil {
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// This check must succeed during TLS, BEFORE sending the user's application
// identity or exporter proof. Hostname-only self-signed acceptance is forbidden.
func VerifyCertificate(rawCerts [][]byte, sni string, a Admission) error {
	if len(rawCerts) != 1 {
		return ErrAuthentication
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return ErrAuthentication
	}
	if cert.VerifyHostname(sni) != nil || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return ErrAuthentication
	}
	if !hmac.Equal(cert.SubjectKeyId, mac(a.PeerKey[:], "certificate-key", cert.RawSubjectPublicKeyInfo)) {
		return ErrAuthentication
	}
	return nil
}
