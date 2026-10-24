package certificates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var challengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type challengeFile struct {
	Host     string `json:"host"`
	Response string `json:"response"`
	Expires  int64  `json:"expires"`
}

func challengePath(dir, host, token string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(host) + "\x00" + token))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func privateDirectory(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("certificate state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("certificate state must be a real private directory")
	}
	return os.Chmod(dir, 0700)
}

func publishChallenge(dir, host, token, response string) (func(), error) {
	if !challengeToken.MatchString(token) || len(response) > 4096 {
		return nil, errors.New("invalid HTTP-01 challenge")
	}
	if err := privateDirectory(dir); err != nil {
		return nil, err
	}
	path := challengePath(dir, host, token)
	data, _ := json.Marshal(challengeFile{Host: strings.ToLower(host), Response: response, Expires: time.Now().Add(6 * time.Minute).Unix()})
	if err := writePrivateAtomic(path, data); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

// ChallengeBroker only serves current challenge files for the exact requested
// host. All issuers and the broker run as the same restricted certificate user.
// It never lists files, redirects requests, or forwards them to another service.
func ChallengeBroker(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		const prefix = "/.well-known/acme-challenge/"
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, prefix) || !challengeToken.MatchString(token) || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if value, _, err := net.SplitHostPort(host); err == nil {
			host = value
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\ \t\r\n") {
			http.NotFound(w, r)
			return
		}
		file, err := os.Open(challengePath(dir, host, token))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		var value challengeFile
		d := json.NewDecoder(io.LimitReader(file, 8192))
		if d.Decode(&value) != nil || value.Host != host || value.Expires <= time.Now().Unix() || value.Expires > time.Now().Add(7*time.Minute).Unix() || len(value.Response) > 4096 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, value.Response)
	})
}

func Validate(options Config) error {
	if options.Host == "" || len(options.Host) > 253 || strings.ContainsAny(options.Host, "/\\ \t\r\n") {
		return errors.New("invalid certificate hostname/IP")
	}
	ip := net.ParseIP(options.Host)
	switch options.Mode {
	case "manual":
		if options.CertFile == "" || options.KeyFile == "" {
			return errors.New("manual certificate and key paths required")
		}
	case "acme-ip", "acme-domain":
		if !options.AcceptTerms {
			return errors.New("explicit acceptance of certificate authority terms required")
		}
		if options.Mode == "acme-ip" && (ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return errors.New("public IP required for acme-ip")
		}
		if options.Mode == "acme-domain" && (ip != nil || !strings.Contains(options.Host, ".") || strings.Contains(options.Host, "*")) {
			return errors.New("DNS name required for acme-domain")
		}
		if options.Mode == "acme-domain" {
			for _, label := range strings.Split(options.Host, ".") {
				if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`).MatchString(label) {
					return errors.New("valid ASCII DNS labels required; use punycode for international domains")
				}
			}
		}
		if !filepath.IsAbs(options.CacheDir) {
			return errors.New("absolute private ACME cache directory required")
		}
	default:
		return errors.New("TLS mode must be manual, acme-ip or acme-domain")
	}
	if options.ChallengeDir != "" && !filepath.IsAbs(options.ChallengeDir) {
		return errors.New("absolute shared challenge directory required")
	}
	return nil
}
