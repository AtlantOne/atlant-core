package tlsprofiles

import (
	"crypto/rand"
	"fmt"
	u "github.com/refraction-networking/utls"
	"math/big"
	"strings"
)

type Profile struct{ ID, Label, Family string }

var profiles = []Profile{
	{"chrome_106", "Chrome 106", "chrome"},
	{"chrome_120", "Chrome 120", "chrome"},
	{"chrome_131", "Chrome 131", "chrome"},
	{"chrome_133", "Chrome 133", "chrome"},
	{"chrome_144", "Chrome 144", "chrome"},
	{"firefox_99", "Firefox 99", "firefox"},
	{"firefox_102", "Firefox 102", "firefox"},
	{"firefox_105", "Firefox 105", "firefox"},
	{"firefox_120", "Firefox 120", "firefox"},
	{"safari_16", "Safari 16", "safari"},
	{"ios_13", "iOS 13", "ios"},
	{"ios_14", "iOS 14", "ios"},
	{"edge_85", "Edge 85", "edge"},
	{"edge_106", "Edge 106", "edge"},
}

func Profiles() []Profile { return append([]Profile(nil), profiles...) }

// Resolve chooses one complete browser preset for a new handshake. The result
// is never used to mutate an already constructed or authenticated ClientHello.
func Resolve(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "", "firefox", "firefox_auto":
		return "firefox_120", nil
	case "chrome", "chrome_auto":
		return "chrome_144", nil
	case "safari", "safari_auto":
		return "safari_16", nil
	case "ios", "iphone":
		return "ios_14", nil
	case "edge":
		return "edge_106", nil
	case "random", "randomized":
		name = "random_browser"
	}
	if strings.HasPrefix(name, "random_") {
		family := strings.TrimPrefix(name, "random_")
		var pool []string
		for _, p := range profiles {
			if family == "browser" || family == p.Family {
				pool = append(pool, p.ID)
			}
		}
		if len(pool) == 0 {
			return "", fmt.Errorf("unsupported TLS profile %q", name)
		}
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return "", fmt.Errorf("choose TLS profile: %w", err)
		}
		return pool[index.Int64()], nil
	}
	for _, p := range profiles {
		if p.ID == name {
			return name, nil
		}
	}
	// Preserve imported legacy names; the caller still checks REALITY key shares.
	switch name {
	case "android", "okhttp", "android_11", "360", "qq":
		return name, nil
	}
	return "", fmt.Errorf("unsupported TLS profile %q", name)
}

func Spec(name string) (u.ClientHelloSpec, error) {
	name, err := Resolve(name)
	if err != nil {
		return u.ClientHelloSpec{}, err
	}
	var id u.ClientHelloID
	switch name {
	case "chrome_106":
		id = u.HelloChrome_106_Shuffle
	case "chrome_120":
		id = u.HelloChrome_120
	case "chrome_131":
		id = u.HelloChrome_131
	case "chrome_133":
		id = u.HelloChrome_133
	case "chrome_144":
		return Chrome144Spec()
	case "firefox_99":
		id = u.HelloFirefox_99
	case "firefox_102":
		id = u.HelloFirefox_102
	case "firefox_105":
		id = u.HelloFirefox_105
	case "firefox_120":
		id = u.HelloFirefox_120
	case "safari_16":
		id = u.HelloSafari_16_0
	case "ios_13":
		id = u.HelloIOS_13
	case "ios_14":
		id = u.HelloIOS_14
	case "edge_85":
		id = u.HelloEdge_85
	case "edge_106":
		id = u.HelloEdge_106
	case "android", "okhttp", "android_11":
		id = u.HelloAndroid_11_OkHttp
	case "360":
		id = u.Hello360_Auto
	case "qq":
		id = u.HelloQQ_Auto
	default:
		return u.ClientHelloSpec{}, fmt.Errorf("unsupported TLS profile %q", name)
	}
	return u.UTLSIdToSpec(id)
}
