package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

type cliProfile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Subscription string `json:"subscription,omitempty"`
	Config       Config `json:"config"`
}

type cliSubscription struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Updated  time.Time `json:"updated"`
	Upload   int64     `json:"upload"`
	Download int64     `json:"download"`
	Total    int64     `json:"total"`
	Expire   int64     `json:"expire"`
}

type cliCatalog struct {
	Version       int               `json:"version"`
	Active        string            `json:"active"`
	Settings      Config            `json:"settings"`
	Profiles      []cliProfile      `json:"profiles"`
	Subscriptions []cliSubscription `json:"subscriptions"`
}

type clientCLI struct {
	dir   string
	state cliCatalog
	in    *bufio.Reader
	out   io.Writer
}

func cliDefaults() Config {
	c := parseAtlantURL("atlant://127.0.0.1:443?wire_version=7")
	c.ServerAddr = ""
	c.Tun = true
	return *c
}

func cliID(text string) string {
	h := sha256.Sum256([]byte(text))
	return hex.EncodeToString(h[:12])
}

func cliText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
}

func handleClientCLI(args []string) bool {
	if len(args) == 0 {
		if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err != nil {
			return false
		}
	} else if args[0] == "cli" {
		args = args[1:]
	} else {
		return false
	}
	if err := runClientCLI(args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Atlant:", err)
		os.Exit(1)
	}
	return true
}

func runClientCLI(args []string, input io.Reader, output io.Writer) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dir = filepath.Join(dir, "atlant", "client")
	if len(args) >= 2 && args[0] == "--state" {
		dir, args = args[1], args[2:]
	}
	if len(args) == 0 {
		args = []string{"menu"}
	}
	if args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(output, cliHelp)
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be owned by this user and have permissions 0700")
	}
	c := &clientCLI{dir: abs, in: bufio.NewReader(input), out: output}
	if args[0] == "menu" {
		return c.menu()
	}
	return c.execute(args)
}

func (c *clientCLI) execute(args []string) error {
	if len(args) == 2 && args[0] == "logs" && args[1] == "follow" {
		return c.logs(args[1:])
	}
	return c.locked(func() error { return c.command(args) })
}

func (c *clientCLI) locked(action func() error) error {
	fd, err := unix.Open(filepath.Join(c.dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another Atlant CLI operation is running")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	c.state = cliCatalog{Version: 1, Settings: cliDefaults()}
	data, err := c.read("catalog.json")
	if err == nil {
		if err := json.Unmarshal(data, &c.state); err != nil {
			return errors.New("invalid catalog; original file preserved")
		}
		if c.state.Version != 1 {
			return errors.New("unsupported catalog version; original file preserved")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return action()
}

func (c *clientCLI) read(name string) ([]byte, error) {
	fd, err := unix.Open(filepath.Join(c.dir, name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private state file must be regular with permissions 0600")
	}
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

func (c *clientCLI) write(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.dir, ".state-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(append(data, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(temp, filepath.Join(c.dir, name)); err != nil {
		return err
	}
	d, err := os.Open(c.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (c *clientCLI) save() error { return c.write("catalog.json", c.state) }

func (c *clientCLI) profile(id string) (*cliProfile, error) {
	if id == "" {
		id = c.state.Active
	}
	if number, err := strconv.Atoi(id); err == nil && number > 0 && number <= len(c.state.Profiles) {
		return &c.state.Profiles[number-1], nil
	}
	for i := range c.state.Profiles {
		if c.state.Profiles[i].ID == id {
			return &c.state.Profiles[i], nil
		}
	}
	return nil, errors.New("profile not found; run profiles list")
}

func cliValidate(cfg Config) error {
	host, port, err := net.SplitHostPort(cfg.ServerAddr)
	n, e := strconv.Atoi(port)
	if err != nil || e != nil || host == "" || n < 1 || n > 65535 {
		return errors.New("server must be host:port")
	}
	if cfg.SNI == "" || strings.ContainsAny(cfg.SNI, "\r\n /:") {
		return errors.New("a valid REALITY SNI is required")
	}
	if cfg.PBK == "" || cfg.ServerPubKey == "" || cfg.User == "" {
		return errors.New("user, PBK and server public key are required")
	}
	if cfg.WireVersion != 7 {
		return errors.New("this CLI creates current wire_version=7 profiles only")
	}
	return cliValidateSettings(cfg)
}

func cliValidateSettings(cfg Config) error {
	member := func(v string, values ...string) bool {
		for _, x := range values {
			if x == v {
				return true
			}
		}
		return false
	}
	if !member(cfg.Transport, "reality", "xhttp", "quic") || !member(cfg.TCPProto, "reality", "xhttp", "quic") || !member(cfg.UDPProto, "tcp", "quic") || !member(cfg.TrafficMode, "split", "tcp", "udp") {
		return errors.New("invalid transport selection")
	}
	if !member(cfg.Fingerprint, "firefox", "firefox_auto", "firefox_120", "chrome", "chrome_144", "safari", "ios", "edge", "randomized") {
		return errors.New("unsupported TLS fingerprint")
	}
	if cfg.MTU < 1200 || cfg.MTU > 9000 || cfg.MinPadding < 0 || cfg.MaxPadding < cfg.MinPadding || cfg.MaxPadding > 4096 || cfg.ChaffingInterval < 1 {
		return errors.New("invalid MTU, padding or chaffing interval")
	}
	if !member(cfg.LogLevel, "debug", "info", "warn", "error", "none") {
		return errors.New("invalid log level")
	}
	host, port, err := net.SplitHostPort(cfg.LocalPort)
	p, pe := strconv.Atoi(port)
	if err != nil || pe != nil || p < 1 || p > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("SOCKS must bind to a loopback IP and valid port")
	}
	if net.ParseIP(cfg.TunDNS) == nil {
		return errors.New("DNS must be an IP address")
	}
	if _, _, err := net.ParseCIDR(cfg.TunAddr); err != nil {
		return errors.New("invalid TUN address")
	}
	if cfg.TunName == "" || len(cfg.TunName) > 15 || strings.ContainsAny(cfg.TunName, "/ \t\r\n") {
		return errors.New("invalid TUN interface name")
	}
	if cfg.Path == "" || !strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, "\r\n") {
		return errors.New("XHTTP path must start with /")
	}
	return nil
}

func cliParseProfile(link string) (cliProfile, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "atlant" {
		return cliProfile{}, errors.New("expected atlant:// link")
	}
	cfg := parseAtlantURL(link)
	if cfg == nil {
		return cliProfile{}, errors.New("invalid Atlant profile")
	}
	if cfg.User == "" && u.User != nil {
		cfg.User = u.User.Username()
	}
	if cfg.WireVersion != 7 {
		return cliProfile{}, errors.New("profile is not current wire_version=7; refresh its subscription")
	}
	if err := cliValidate(*cfg); err != nil {
		return cliProfile{}, err
	}
	name := u.Fragment
	if name == "" {
		name = u.Host
	}
	name = cliText(name)
	// Identity excludes authentication keys so a subscription key rotation keeps selection.
	id := cliID(cfg.ServerAddr + "\x00" + cfg.User + "\x00" + u.Query().Get("server_id") + "\x00" + u.Query().Get("inbound_id"))
	return cliProfile{ID: id, Name: name, Config: *cfg}, nil
}

func cliShare(p cliProfile) string {
	cfg := p.Config
	q := url.Values{"wire_version": {"7"}, "sni": {cfg.SNI}, "pbk": {cfg.PBK}, "user": {cfg.User}, "server_pub_key": {cfg.ServerPubKey}, "path": {cfg.Path}}
	return (&url.URL{Scheme: "atlant", Host: cfg.ServerAddr, RawQuery: q.Encode(), Fragment: p.Name}).String()
}

func (c *clientCLI) effective() (Config, error) {
	p, err := c.profile("")
	if err != nil {
		return Config{}, err
	}
	cfg := c.state.Settings
	cfg.ServerAddr, cfg.SNI, cfg.PBK, cfg.User = p.Config.ServerAddr, p.Config.SNI, p.Config.PBK, p.Config.User
	cfg.ServerPubKey, cfg.WireVersion, cfg.Path = p.Config.ServerPubKey, p.Config.WireVersion, p.Config.Path
	return cfg, cliValidate(cfg)
}

func (c *clientCLI) command(args []string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "help":
		fmt.Fprint(c.out, cliHelp)
		return nil
	case "status":
		return c.status()
	case "connect":
		return c.connect()
	case "disconnect":
		return c.disconnect()
	case "reconnect":
		if err := c.disconnect(); err != nil {
			return err
		}
		return c.connect()
	case "profiles":
		return c.profiles(args[1:])
	case "subscriptions":
		return c.subscriptions(args[1:])
	case "settings":
		return c.settings(args[1:])
	case "logs":
		return c.logs(args[1:])
	case "ping":
		id := ""
		if len(args) > 1 {
			id = args[1]
		}
		p, err := c.profile(id)
		if err != nil {
			return err
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", p.Config.ServerAddr, 3*time.Second)
		if err != nil {
			return errors.New("TCP endpoint unreachable (this is not a QUIC test)")
		}
		conn.Close()
		fmt.Fprintf(c.out, "%s: TCP connect %s (not authenticated VPN RTT)\n", p.Name, time.Since(start).Round(time.Millisecond))
		return nil
	case "qr":
		if len(args) != 3 {
			return errors.New("usage: qr profile|subscription ID")
		}
		var link string
		if args[1] == "profile" {
			p, err := c.profile(args[2])
			if err != nil {
				return err
			}
			link = cliShare(*p)
		} else if args[1] == "subscription" {
			for _, s := range c.state.Subscriptions {
				if s.ID == args[2] {
					link = s.URL
				}
			}
		} else {
			return errors.New("unknown QR source")
		}
		if link == "" {
			return errors.New("subscription not found")
		}
		cmd := exec.Command("qrencode", "-t", "ANSIUTF8")
		cmd.Stdin = strings.NewReader(link)
		cmd.Stdout = c.out
		cmd.Stderr = c.out
		if err := cmd.Run(); err != nil {
			return errors.New("terminal QR requires qrencode; use profiles share or subscriptions share for the link")
		}
		return nil
	default:
		return errors.New("unknown command; run cli help")
	}
}

func (c *clientCLI) profiles(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		for _, s := range c.state.Subscriptions {
			fmt.Fprintf(c.out, "Subscription: %s [%s]\n", s.Name, s.ID)
			for _, p := range c.state.Profiles {
				if p.Subscription == s.ID {
					c.printProfile(p, "  ")
				}
			}
		}
		fmt.Fprintln(c.out, "Local servers:")
		for _, p := range c.state.Profiles {
			if p.Subscription == "" {
				c.printProfile(p, "")
			}
		}
		return nil
	}
	if args[0] == "import" {
		if len(args) != 2 {
			return errors.New("usage: profiles import FILE (Atlant links or Linux JSON configuration)")
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
		if err != nil {
			return err
		}
		if len(data) > 2<<20 {
			return errors.New("import too large")
		}
		var profiles []cliProfile
		if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
			cfg := cliDefaults()
			if err := json.Unmarshal(data, &cfg); err != nil {
				return errors.New("invalid JSON configuration")
			}
			if err := cliValidate(cfg); err != nil {
				return err
			}
			profiles = []cliProfile{{ID: cliID(cfg.ServerAddr + "\x00" + cfg.User), Name: cfg.ServerAddr, Config: cfg}}
		} else {
			profiles, err = cliParseLinks(string(data))
			if err != nil {
				return err
			}
		}
		for _, p := range profiles {
			c.addProfile(p)
		}
		return c.save()
	}
	if args[0] == "add" {
		if len(args) != 1 {
			return errors.New("profiles add reads a private link from stdin; do not put keys in shell arguments")
		}
		link, err := c.prompt("Atlant link (contains credentials): ")
		if err != nil {
			return err
		}
		p, err := cliParseProfile(link)
		if err != nil {
			return err
		}
		c.addProfile(p)
		return c.save()
	}
	if len(args) < 2 {
		return errors.New("profile ID required")
	}
	p, err := c.profile(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "select":
		c.state.Active = p.ID
		return c.save()
	case "rename":
		if len(args) != 3 || strings.TrimSpace(args[2]) == "" {
			return errors.New("usage: profiles rename ID NAME")
		}
		p.Name = args[2]
		return c.save()
	case "edit":
		if p.Subscription != "" {
			return errors.New("subscription profiles are managed by their source; import a local copy to edit")
		}
		next := *p
		for _, field := range []struct {
			label string
			value *string
		}{
			{"Name", &next.Name}, {"Server (host:port)", &next.Config.ServerAddr}, {"REALITY SNI", &next.Config.SNI}, {"User", &next.Config.User}, {"PBK", &next.Config.PBK}, {"Server public key", &next.Config.ServerPubKey}, {"XHTTP path", &next.Config.Path},
		} {
			value, err := c.prompt(field.label + " (Enter keeps current): ")
			if err != nil {
				return err
			}
			if value != "" {
				*field.value = value
			}
		}
		if err := cliValidate(next.Config); err != nil {
			return err
		}
		*p = next
		return c.save()
	case "share":
		fmt.Fprintln(c.out, cliShare(*p))
		return nil
	case "delete":
		if c.alive() {
			return errors.New("disconnect before removing profiles")
		}
		if !c.confirm("Delete this profile?") {
			return nil
		}
		id := p.ID
		for i, p := range c.state.Profiles {
			if p.ID == id {
				c.state.Profiles = append(c.state.Profiles[:i], c.state.Profiles[i+1:]...)
				break
			}
		}
		if c.state.Active == id {
			c.state.Active = ""
		}
		return c.save()
	default:
		return errors.New("unknown profile operation")
	}
}

func (c *clientCLI) addProfile(p cliProfile) {
	for i, old := range c.state.Profiles {
		if old.ID == p.ID && old.Subscription == "" {
			c.state.Profiles[i] = p
			return
		}
	}
	c.state.Profiles = append(c.state.Profiles, p)
	if c.state.Active == "" {
		c.state.Active = p.ID
	}
}

func (c *clientCLI) printProfile(p cliProfile, indent string) {
	selected := " "
	if p.ID == c.state.Active {
		selected = "*"
	}
	number := 0
	for i, item := range c.state.Profiles {
		if item.ID == p.ID {
			number = i + 1
			break
		}
	}
	fmt.Fprintf(c.out, "%s%s %d. %s  %s  [%s]\n", indent, selected, number, cliText(p.Name), cliText(p.Config.ServerAddr), p.ID)
}

func cliParseLinks(body string) ([]cliProfile, error) {
	text := strings.TrimSpace(body)
	if !strings.Contains(text, "atlant://") {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if data, err := enc.DecodeString(text); err == nil {
				text = string(data)
				break
			}
		}
	}
	var profiles []cliProfile
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := cliParseProfile(line)
		if err != nil {
			return nil, errors.New("subscription/import contains an invalid or unsupported profile; previous data retained")
		}
		if !seen[p.ID] {
			profiles = append(profiles, p)
			seen[p.ID] = true
		}
		if len(profiles) > 256 {
			return nil, errors.New("too many profiles")
		}
	}
	if len(profiles) == 0 {
		return nil, errors.New("no Atlant profiles; previous data retained")
	}
	return profiles, nil
}

func cliSubscriptionURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid subscription URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()) {
		return errors.New("subscription requires HTTPS (HTTP allowed only on loopback)")
	}
	return nil
}

func cliFetchSubscription(raw string) (cliSubscription, []cliProfile, error) {
	if err := cliSubscriptionURL(raw); err != nil {
		return cliSubscription{}, nil, err
	}
	u, _ := url.Parse(raw)
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many redirects")
		}
		return cliSubscriptionURL(r.URL.String())
	}}
	resp, err := client.Get(raw)
	if err != nil {
		return cliSubscription{}, nil, errors.New("subscription request failed; check HTTPS certificate and connectivity")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return cliSubscription{}, nil, fmt.Errorf("subscription returned HTTP %d; previous data retained", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		return cliSubscription{}, nil, errors.New("subscription unreadable or exceeds 2 MiB")
	}
	profiles, err := cliParseLinks(string(body))
	if err != nil {
		return cliSubscription{}, nil, err
	}
	s := cliSubscription{ID: cliID(raw), Name: u.Hostname(), URL: raw, Updated: time.Now()}
	for _, part := range strings.Split(resp.Header.Get("Subscription-Userinfo"), ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch kv[0] {
		case "upload":
			s.Upload = n
		case "download":
			s.Download = n
		case "total":
			s.Total = n
		case "expire":
			s.Expire = n
		}
	}
	return s, profiles, nil
}

func (c *clientCLI) replaceSubscription(s cliSubscription, profiles []cliProfile) {
	replaced := false
	for i, old := range c.state.Subscriptions {
		if old.ID == s.ID {
			s.Name = old.Name
			c.state.Subscriptions[i] = s
			replaced = true
			break
		}
	}
	if !replaced {
		c.state.Subscriptions = append(c.state.Subscriptions, s)
	}
	kept := []cliProfile{}
	position := -1
	owned := false
	for _, p := range c.state.Profiles {
		if p.Subscription == s.ID {
			if position < 0 {
				position = len(kept)
			}
			owned = owned || p.ID == c.state.Active
		} else {
			kept = append(kept, p)
		}
	}
	if position < 0 {
		position = len(kept)
	}
	newProfiles := []cliProfile{}
	matched := false
	for _, p := range profiles {
		p.ID = cliID(s.ID + ":" + p.ID)
		p.Subscription = s.ID
		if p.ID == c.state.Active {
			matched = true
		}
		newProfiles = append(newProfiles, p)
	}
	c.state.Profiles = append(append(append([]cliProfile{}, kept[:position]...), newProfiles...), kept[position:]...)
	if owned && !matched {
		c.state.Active = ""
	}
	if c.state.Active == "" && len(newProfiles) > 0 {
		c.state.Active = newProfiles[0].ID
	}
}

func (c *clientCLI) subscriptions(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		for i, s := range c.state.Subscriptions {
			fmt.Fprintf(c.out, "%d. %s [%s]  updated %s\n", i+1, cliText(s.Name), s.ID, s.Updated.Format(time.RFC3339))
			if s.Total > 0 {
				remaining := s.Total
				if s.Upload >= remaining {
					remaining = 0
				} else {
					remaining -= s.Upload
				}
				if s.Download >= remaining {
					remaining = 0
				} else {
					remaining -= s.Download
				}
				used := float64(s.Total-remaining) / float64(s.Total)
				filled := int(used * 20)
				fmt.Fprintf(c.out, "[%s%s] %.2f / %.2f GiB remaining\n", strings.Repeat("#", filled), strings.Repeat("-", 20-filled), float64(remaining)/(1<<30), float64(s.Total)/(1<<30))
			} else {
				fmt.Fprintln(c.out, "Unlimited")
			}
			if s.Expire > 0 {
				fmt.Fprintln(c.out, "Expires:", time.Unix(s.Expire, 0).Format(time.RFC3339))
			}
		}
		return nil
	}
	if args[0] == "add" {
		if len(args) != 1 {
			return errors.New("subscriptions add reads URL from stdin to avoid shell history")
		}
		raw, err := c.prompt("Subscription URL: ")
		if err != nil {
			return err
		}
		s, profiles, err := cliFetchSubscription(raw)
		if err != nil {
			return err
		}
		c.replaceSubscription(s, profiles)
		return c.save()
	}
	if len(args) < 2 {
		return errors.New("subscription ID or all required")
	}
	if number, err := strconv.Atoi(args[1]); err == nil && number > 0 && number <= len(c.state.Subscriptions) {
		args[1] = c.state.Subscriptions[number-1].ID
	}
	if args[0] == "update" {
		found := false
		for _, old := range append([]cliSubscription{}, c.state.Subscriptions...) {
			if args[1] != "all" && old.ID != args[1] {
				continue
			}
			found = true
			s, profiles, err := cliFetchSubscription(old.URL)
			if err != nil {
				return err
			}
			s.ID = old.ID
			c.replaceSubscription(s, profiles)
		}
		if !found {
			return errors.New("subscription not found")
		}
		return c.save()
	}
	index := -1
	for i, s := range c.state.Subscriptions {
		if s.ID == args[1] {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("subscription not found")
	}
	switch args[0] {
	case "rename":
		if len(args) != 3 || strings.TrimSpace(args[2]) == "" {
			return errors.New("name required")
		}
		c.state.Subscriptions[index].Name = args[2]
		return c.save()
	case "share":
		fmt.Fprintln(c.out, c.state.Subscriptions[index].URL)
		return nil
	case "delete":
		if c.alive() {
			return errors.New("disconnect before deleting subscriptions")
		}
		if !c.confirm("Delete subscription and its profiles?") {
			return nil
		}
		id := c.state.Subscriptions[index].ID
		c.state.Subscriptions = append(c.state.Subscriptions[:index], c.state.Subscriptions[index+1:]...)
		kept := []cliProfile{}
		for _, p := range c.state.Profiles {
			if p.Subscription == id {
				if c.state.Active == p.ID {
					c.state.Active = ""
				}
			} else {
				kept = append(kept, p)
			}
		}
		c.state.Profiles = kept
		return c.save()
	default:
		return errors.New("unknown subscription operation")
	}
}

func (c *clientCLI) settings(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg := c.state.Settings
		fmt.Fprintf(c.out, "Connection\n  TUN: %t   SOCKS: %s\n  Traffic: %s   TCP: %s   UDP: %s   Carrier: %s\n  TLS fingerprint: %s   Multiplexing: %t\n\nNetwork\n  MTU: %d   DNS: %s   FakeDNS: %t\n  TUN name: %s   Address: %s\n  IPv6 blocked: %t\n\nPadding and background traffic\n  Padding: %t   Range: %d–%d bytes\n  Chaffing: %t   Interval: %d seconds\n\nDiagnostics\n  Log level: %s\n\nSettings apply on reconnect. Field names for scripts:\n", cfg.Tun, cfg.LocalPort, cfg.TrafficMode, cfg.TCPProto, cfg.UDPProto, cfg.Transport, cfg.Fingerprint, cfg.Mux, cfg.MTU, cfg.TunDNS, cfg.FakeDNS, cfg.TunName, cfg.TunAddr, cfg.DisableIPv6, cfg.PaddingEnabled, cfg.MinPadding, cfg.MaxPadding, cfg.ChaffingEnabled, cfg.ChaffingInterval, cfg.LogLevel)
		fmt.Fprintln(c.out, "tun, local, transport, traffic_mode, tcp_proto, udp_proto, fingerprint, mux, mtu, tun_dns, fake_dns, tun_name, tun_addr, tun_ipv6_addr, tun_dns_ipv6, disable_ipv6, padding_enabled, min_padding, max_padding, traffic_padding, chaffing_enabled, chaffing_interval, chaffing_min_bytes, chaffing_max_bytes, log_level")
		return nil
	}
	if args[0] == "reset" {
		if !c.confirm("Reset client settings (keep servers and subscriptions)?") {
			return nil
		}
		c.state.Settings = cliDefaults()
		return c.save()
	}
	if len(args) != 3 || args[0] != "set" {
		return errors.New("usage: settings set FIELD VALUE")
	}
	// Catalog settings never contain a profile's credentials.
	allowed := map[string]bool{}
	for _, name := range strings.Fields("local tun tun_name tun_addr tun_dns tun_ipv6_addr tun_dns_ipv6 disable_ipv6 transport path mode content_type traffic_mode udp_proto udp_mode tcp_proto mtu mux log_level fake_dns traffic_padding fingerprint padding_enabled min_padding max_padding chaffing_enabled chaffing_interval chaffing_min_bytes chaffing_max_bytes") {
		allowed[name] = true
	}
	if !allowed[args[1]] {
		return errors.New("unknown or profile-owned setting; run settings show")
	}
	next := c.state.Settings
	value := reflect.ValueOf(&next).Elem()
	typ := value.Type()
	found := false
	for i := 0; i < typ.NumField(); i++ {
		if strings.Split(typ.Field(i).Tag.Get("json"), ",")[0] != args[1] {
			continue
		}
		f := value.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(args[2])
		case reflect.Bool:
			v, err := strconv.ParseBool(args[2])
			if err != nil {
				return errors.New("expected true or false")
			}
			f.SetBool(v)
		case reflect.Int:
			v, err := strconv.ParseInt(args[2], 10, 32)
			if err != nil {
				return errors.New("expected integer")
			}
			f.SetInt(v)
		default:
			return errors.New("unsupported setting type")
		}
		found = true
		break
	}
	if !found {
		return errors.New("unknown setting")
	}
	if err := cliValidateSettings(next); err != nil {
		return err
	}
	c.state.Settings = next
	return c.save()
}

type cliProcess struct {
	PID        int       `json:"pid"`
	Start      string    `json:"start"`
	Executable string    `json:"executable"`
	Profile    string    `json:"profile"`
	Since      time.Time `json:"since"`
}

func cliProcStart(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return "", errors.New("process exited")
	}
	return fields[19], nil
}

func (c *clientCLI) process() (cliProcess, error) {
	var p cliProcess
	data, err := c.read("process.json")
	if err != nil {
		return p, err
	}
	if err = json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	if p.PID < 2 {
		return p, errors.New("invalid process ID")
	}
	start, err := cliProcStart(p.PID)
	if err != nil || start != p.Start {
		return p, errors.New("client is stopped")
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", p.PID))
	if err != nil || exe != p.Executable {
		return p, errors.New("process identity mismatch; refusing to signal it")
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", p.PID))
	if err != nil || !strings.Contains(string(cmdline), "\x00-c\x00"+filepath.Join(c.dir, "runtime.json")+"\x00") {
		return p, errors.New("process arguments mismatch")
	}
	return p, nil
}

func (c *clientCLI) alive() bool { _, err := c.process(); return err == nil }

func (c *clientCLI) status() error {
	p, err := c.process()
	if err != nil {
		fmt.Fprintln(c.out, "Disconnected")
		return nil
	}
	fmt.Fprintf(c.out, "Running: PID %d, profile %s, since %s\n", p.PID, p.Profile, p.Since.Format(time.RFC3339))
	if data, err := c.read("runtime.json"); err == nil {
		var cfg Config
		if json.Unmarshal(data, &cfg) == nil {
			fmt.Fprintf(c.out, "SOCKS: %s, TUN: %t, transport: %s / TCP %s / UDP %s\n", cfg.LocalPort, cfg.Tun, cfg.Transport, cfg.TCPProto, cfg.UDPProto)
		}
	}
	return nil
}

func (c *clientCLI) connect() error {
	if c.alive() {
		return errors.New("client already running; disconnect or reconnect first")
	}
	cfg, err := c.effective()
	if err != nil {
		return err
	}
	if cfg.Tun && os.Geteuid() != 0 {
		return errors.New("TUN requires root; run sudo with the same --state directory or set tun false for SOCKS")
	}
	if err := c.write("runtime.json", cfg); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(c.dir, "client.log"), unix.O_CREAT|unix.O_APPEND|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	log := os.NewFile(uintptr(fd), "client.log")
	defer log.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	cmd := exec.Command(exe, "-c", filepath.Join(c.dir, "runtime.json"))
	cmd.Stdout, cmd.Stderr = log, log
	cmd.ExtraFiles = []*os.File{readyWrite}
	cmd.Env = append(os.Environ(), "ATLANT_CLI_READY_FD=3")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	readyWrite.Close()
	pid := cmd.Process.Pid
	start, err := cliProcStart(pid)
	if err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		return err
	}
	p := cliProcess{pid, start, exe, c.state.Active, time.Now()}
	if err := c.write("process.json", p); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		return err
	}
	go cmd.Wait()
	if err := readyRead.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		_ = c.disconnect()
		return err
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err == nil && ready[0] == 1 && c.alive() {
		fmt.Fprintln(c.out, "Client started (local SOCKS ready; remote connectivity is not yet verified).")
		return nil
	}
	_ = c.disconnect()
	return errors.New("client failed to become ready; run logs")
}

// The parent receives readiness from its own core, never from an unrelated
// SOCKS listener that happens to use the same port.
func notifyClientCLIReady() {
	if os.Getenv("ATLANT_CLI_READY_FD") != "3" {
		return
	}
	f := os.NewFile(3, "cli-ready")
	if f != nil {
		_, _ = f.Write([]byte{1})
		_ = f.Close()
	}
	_ = os.Unsetenv("ATLANT_CLI_READY_FD")
}

func (c *clientCLI) disconnect() error {
	p, err := c.process()
	if err != nil {
		fmt.Fprintln(c.out, "Already stopped")
		return nil
	}
	// pidfd prevents a recycled PID from receiving a signal after identity checks.
	fd, err := unix.PidfdOpen(p.PID, 0)
	if err != nil {
		return fmt.Errorf("cannot safely stop client using pidfd: %w", err)
	}
	defer unix.Close(fd)
	if _, err := c.process(); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		return err
	}
	until := time.Now().Add(15 * time.Second)
	for c.alive() && time.Now().Before(until) {
		time.Sleep(100 * time.Millisecond)
	}
	if c.alive() {
		return errors.New("client did not stop; no forced kill performed to preserve TUN cleanup")
	}
	for _, name := range []string{"process.json", "runtime.json"} {
		if err := os.Remove(filepath.Join(c.dir, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	fmt.Fprintln(c.out, "Disconnected; core finished cleanup.")
	return nil
}

func (c *clientCLI) logs(args []string) error {
	if len(args) > 0 && args[0] == "path" {
		fmt.Fprintln(c.out, filepath.Join(c.dir, "client.log"))
		return nil
	}
	if len(args) > 0 && args[0] == "clear" {
		if !c.confirm("Clear client log?") {
			return nil
		}
		fd, err := unix.Open(filepath.Join(c.dir, "client.log"), unix.O_WRONLY|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return unix.Close(fd)
	}
	if len(args) > 0 && args[0] == "follow" {
		ctx, cancel := signalContext()
		defer cancel()
		cmd := exec.CommandContext(ctx, "tail", "-n", "50", "-F", "--", filepath.Join(c.dir, "client.log"))
		cmd.Stdout = c.out
		cmd.Stderr = c.out
		err := cmd.Run()
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	fd, err := unix.Open(filepath.Join(c.dir, "client.log"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			fmt.Fprintln(c.out, "No log yet")
			return nil
		}
		return err
	}
	f := os.NewFile(uintptr(fd), "client.log")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	offset := info.Size() - 128*1024
	if offset < 0 {
		offset = 0
	}
	if _, err = f.Seek(offset, 0); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 128*1024))
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 50 {
		lines = lines[len(lines)-50:]
	}
	fmt.Fprintln(c.out, strings.Join(lines, "\n"))
	return nil
}

func (c *clientCLI) prompt(label string) (string, error) {
	fmt.Fprint(c.out, label)
	line, err := c.in.ReadString('\n')
	if err != nil && !(err == io.EOF && len(line) > 0) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
func (c *clientCLI) confirm(label string) bool {
	answer, err := c.prompt(label + " [y/N]: ")
	return err == nil && strings.EqualFold(answer, "y")
}

func (c *clientCLI) menu() error {
	for {
		fmt.Fprint(c.out, "\nAtlant — Linux client\n1 Connection\n2 Servers\n3 Subscriptions\n4 Settings\n5 Journal\n6 Help / commands\n0 Exit (connection stays running)\n")
		choice, err := c.prompt("> ")
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "0" {
			return nil
		}
		var command []string
		switch choice {
		case "1":
			op, err := c.prompt("status / connect / disconnect / reconnect / ping: ")
			if err != nil {
				return err
			}
			command = []string{op}
		case "2":
			if err := c.locked(func() error { return c.profiles(nil) }); err != nil {
				fmt.Fprintln(c.out, "Error:", err)
			}
			op, err := c.prompt("add / import / select / edit / rename / delete / share / qr / back: ")
			if err != nil {
				return err
			}
			if op == "back" {
				continue
			}
			command = []string{"profiles", op}
			if op != "add" {
				id, err := c.prompt("Profile ID (or file path for import): ")
				if err != nil {
					return err
				}
				command = append(command, id)
			}
			if op == "rename" {
				name, err := c.prompt("New name: ")
				if err != nil {
					return err
				}
				command = append(command, name)
			}
			if op == "qr" {
				command = []string{"qr", "profile", command[2]}
			}
		case "3":
			if err := c.locked(func() error { return c.subscriptions(nil) }); err != nil {
				fmt.Fprintln(c.out, "Error:", err)
			}
			op, err := c.prompt("add / update / rename / delete / share / qr / back: ")
			if err != nil {
				return err
			}
			if op == "back" {
				continue
			}
			command = []string{"subscriptions", op}
			if op != "add" {
				id, err := c.prompt("Subscription ID (or all for update): ")
				if err != nil {
					return err
				}
				command = append(command, id)
			}
			if op == "rename" {
				name, err := c.prompt("New name: ")
				if err != nil {
					return err
				}
				command = append(command, name)
			}
			if op == "qr" {
				command = []string{"qr", "subscription", command[2]}
			}
		case "4":
			if err := c.locked(func() error { return c.settings(nil) }); err != nil {
				fmt.Fprintln(c.out, "Error:", err)
			}
			op, err := c.prompt("set / reset / back: ")
			if err != nil {
				return err
			}
			if op == "back" {
				continue
			}
			command = []string{"settings", op}
			if op == "set" {
				key, err := c.prompt("Setting name: ")
				if err != nil {
					return err
				}
				value, err := c.prompt("Value: ")
				if err != nil {
					return err
				}
				command = append(command, key, value)
			}
		case "5":
			op, err := c.prompt("show / follow / clear / path / back: ")
			if err != nil {
				return err
			}
			if op == "back" {
				continue
			}
			command = []string{"logs", op}
		case "6":
			fmt.Fprint(c.out, cliHelp)
			continue
		default:
			fmt.Fprintln(c.out, "Choose 0–6")
			continue
		}
		if err := c.execute(command); err != nil {
			fmt.Fprintln(c.out, "Error:", err)
		}
	}
}

const cliHelp = `Atlant Linux client
  atlant-linux cli [--state PRIVATE_DIRECTORY] [COMMAND]
  atlant-linux cli                     Interactive menu
  atlant-linux cli connect|disconnect|reconnect|status
  atlant-linux cli profiles list|add|import FILE|select ID|edit ID|rename ID NAME|delete ID|share ID
  atlant-linux cli subscriptions list|add|update ID|update all|rename ID NAME|delete ID|share ID
  atlant-linux cli settings show|set FIELD VALUE|reset
  atlant-linux cli ping [PROFILE_ID]    TCP endpoint reachability, not tunnel RTT
  atlant-linux cli qr profile|subscription ID   Terminal QR (requires qrencode)
  atlant-linux cli logs [show|follow|clear|path]

Links are read from stdin, not command arguments. Share/QR reveals credentials.
Settings apply on reconnect. The first imported server is selected automatically.
TUN requires root. SOCKS is loopback-only. Exit leaves the connection running;
use disconnect to stop it and let the core remove its routes and firewall rules.
State directory: $XDG_CONFIG_HOME/atlant/client (0700), files 0600.
Use the same explicit --state directory for commands started under sudo.
Linux per-application/domain split routing and desktop theme are not implemented
by this CLI. It does not pretend that saving those Windows settings enables them.
The existing foreground core flags (-c, -config, -tun, etc.) remain available.
`

// Kept separate so following logs can stop on Ctrl+C without stopping the core.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
