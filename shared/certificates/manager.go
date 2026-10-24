package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/crypto/acme"
)

type Config struct {
	Mode            string `json:"mode"` // manual, acme-ip, acme-domain.
	Host            string `json:"host"`
	CertFile        string `json:"cert_file,omitempty"`
	KeyFile         string `json:"key_file,omitempty"`
	CacheDir        string `json:"cache_dir,omitempty"`
	Email           string `json:"email,omitempty"`
	AcceptTerms     bool   `json:"accept_terms"`
	Staging         bool   `json:"staging"`
	ChallengeListen string `json:"challenge_listen,omitempty"`
	ChallengeDir    string `json:"challenge_dir,omitempty"`
	RequireContext  bool   `json:"-"`
}

type Manager struct {
	options          Config
	mu               sync.RWMutex
	certificate      *tls.Certificate
	challenges       map[string]string
	directoryURL     string // test-only dependency injection; never a JSON setting
	lastManualReload time.Time
	lastAttempt      time.Time
	lastError        string
	listening        bool
}

func subscriptionRenewalDue(leaf *x509.Certificate, now time.Time) bool {
	if leaf == nil {
		return true
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return lifetime <= 0 || !now.Before(leaf.NotAfter.Add(-lifetime/3))
}

func (m *Manager) loadPair(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("invalid HTTPS certificate/key pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname(m.options.Host); err != nil {
		return errors.New("certificate does not match HTTPS domain/IP")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("HTTPS certificate is not currently valid")
	}
	cert.Leaf = leaf
	m.mu.Lock()
	m.certificate = &cert
	m.mu.Unlock()
	return nil
}

func (m *Manager) reload() error {
	certPath, keyPath := m.options.CertFile, m.options.KeyFile
	if m.options.Mode != "manual" {
		certPath = filepath.Join(m.options.CacheDir, "subscription.pem")
		keyPath = certPath
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	if m.options.Mode != "manual" {
		found := false
		for rest := cert; len(rest) > 0; {
			block, tail := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = tail
			if block.Type == "ATLANT CERTIFICATE CONTEXT" {
				found = true
				if string(block.Bytes) != string(m.cacheContext()) {
					return errors.New("cached certificate belongs to another CA/profile or identity")
				}
			}
		}
		if !found && m.options.RequireContext {
			return errors.New("cached certificate context missing; a fresh issuance is required")
		}
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	return m.loadPair(cert, key)
}

func (m *Manager) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Manual files can be replaced by an external issuer. Keep a previously
	// valid pair if a non-atomic external rotation temporarily mismatches files.
	m.mu.Lock()
	reload := m.options.Mode == "manual" && time.Since(m.lastManualReload) >= time.Second
	if reload {
		m.lastManualReload = time.Now()
	}
	m.mu.Unlock()
	if reload {
		_ = m.reload()
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.certificate == nil || !time.Now().Before(m.certificate.Leaf.NotAfter) {
		return nil, errors.New("HTTPS certificate unavailable")
	}
	return m.certificate, nil
}

func writePrivateAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".atlant-pem-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replacePrivateFile(f.Name(), path)
}

func (m *Manager) issue(ctx context.Context) (resultErr error) {
	return m.issueIfNeeded(ctx, true)
}

func (m *Manager) issueIfNeeded(ctx context.Context, force bool) (resultErr error) {
	defer func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if resultErr != nil {
			m.lastError = "Certificate issuance/renewal failed; check logs and HTTP-01 reachability"
		} else {
			m.lastError = ""
		}
	}()
	dir := m.options.CacheDir
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("ACME cache must be a private real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(dir, ".issuer.lock"), flock.SetPermissions(0600))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		_ = lock.Close()
		return errors.New("another certificate issuer owns this cache")
	}
	defer lock.Close()
	if !force {
		if err := m.reload(); err == nil && !m.RenewalDue(time.Now()) {
			return nil
		}
	}
	m.mu.Lock()
	m.lastAttempt = time.Now()
	m.mu.Unlock()
	accountPath := filepath.Join(dir, "account.pem")
	var accountKey *ecdsa.PrivateKey
	if data, err := os.ReadFile(accountPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New("invalid ACME account; refusing replacement")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		accountKey = key
	} else if os.IsNotExist(err) {
		accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(accountKey)
		if err != nil {
			return err
		}
		if err := writePrivateAtomic(accountPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
			return err
		}
	} else {
		return err
	}
	directory := m.directory()
	client := &acme.Client{Key: accountKey, DirectoryURL: directory, HTTPClient: &http.Client{Timeout: 30 * time.Second}}
	account := &acme.Account{}
	if m.options.Email != "" {
		account.Contact = []string{"mailto:" + m.options.Email}
	}
	if _, err := client.Register(ctx, account, func(string) bool { return m.options.AcceptTerms }); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return err
	}
	ids := acme.DomainIDs(m.options.Host)
	var options []acme.OrderOption
	if m.options.Mode == "acme-ip" {
		ids = acme.IPIDs(m.options.Host)
		options = []acme.OrderOption{acme.WithOrderIssuanceProfile("shortlived")}
	}
	order, err := client.AuthorizeOrder(ctx, ids, options...)
	if err != nil {
		return err
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return err
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "http-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return errors.New("CA does not offer HTTP-01")
		}
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(challenge.Token)
		m.mu.Lock()
		m.challenges[path] = response
		m.mu.Unlock()
		defer func() { m.mu.Lock(); delete(m.challenges, path); m.mu.Unlock() }()
		if m.options.ChallengeDir != "" {
			remove, err := publishChallenge(m.options.ChallengeDir, m.options.Host, challenge.Token, response)
			if err != nil {
				return err
			}
			defer remove()
		}
		if _, err := client.Accept(ctx, challenge); err != nil {
			return err
		}
		if _, err := client.WaitAuthorization(ctx, auth.URI); err != nil {
			return err
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{}}
	if ip := net.ParseIP(m.options.Host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{m.options.Host}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, leafKey)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return err
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	for _, der := range chain {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "ATLANT CERTIFICATE CONTEXT", Bytes: m.cacheContext()})...)
	// Validate before replacing the existing good bundle. Both parts in ONE
	// atomic file avoid a cert/key mismatch across process crashes.
	checker := &Manager{options: m.options}
	if err := checker.loadPair(bundle, bundle); err != nil {
		return err
	}
	if err := writePrivateAtomic(filepath.Join(dir, "subscription.pem"), bundle); err != nil {
		return err
	}
	return m.loadPair(bundle, bundle)
}

func (m *Manager) directory() string {
	if m.directoryURL != "" {
		return m.directoryURL
	}
	if m.options.Staging {
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	return "https://acme-v02.api.letsencrypt.org/directory"
}
func (m *Manager) cacheContext() []byte {
	data, _ := json.Marshal(struct{ Host, Mode, Directory string }{strings.ToLower(m.options.Host), m.options.Mode, m.directory()})
	return data
}

func (m *Manager) challengeHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if r.Method != http.MethodGet || !strings.EqualFold(strings.Trim(host, "[]"), m.options.Host) {
		http.NotFound(w, r)
		return
	}
	m.mu.RLock()
	value, ok := m.challenges[r.URL.Path]
	m.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(value))
}

func New(options Config) *Manager {
	return &Manager{options: options, challenges: make(map[string]string)}
}
func (m *Manager) Reload() error                    { return m.reload() }
func (m *Manager) Issue(ctx context.Context) error  { return m.issue(ctx) }
func (m *Manager) Ensure(ctx context.Context) error { return m.issueIfNeeded(ctx, false) }
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.getCertificate(hello)
}
func (m *Manager) ChallengeHandler(w http.ResponseWriter, r *http.Request) { m.challengeHandler(w, r) }
func (m *Manager) BundlePath() string                                      { return filepath.Join(m.options.CacheDir, "subscription.pem") }
func (m *Manager) RenewalDue(now time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var leaf *x509.Certificate
	if m.certificate != nil {
		leaf = m.certificate.Leaf
	}
	return subscriptionRenewalDue(leaf, now)
}
func (m *Manager) SetError(message string)     { m.mu.Lock(); m.lastError = message; m.mu.Unlock() }
func (m *Manager) SetListening(listening bool) { m.mu.Lock(); m.listening = listening; m.mu.Unlock() }
func (m *Manager) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := map[string]any{"listening": m.listening, "mode": m.options.Mode, "last_attempt": m.lastAttempt, "error": m.lastError}
	if m.certificate != nil {
		leaf := m.certificate.Leaf
		status["not_after"] = leaf.NotAfter
		status["renew_before"] = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	}
	return status
}
func WritePrivateAtomic(path string, data []byte) error { return writePrivateAtomic(path, data) }
