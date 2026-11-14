package tlsprofiles

import (
	u "github.com/refraction-networking/utls"
	"net"
	"testing"
)

func TestCatalogProfilesMarshalWithNativeRealityKeyShare(t *testing.T) {
	for _, profile := range Profiles() {
		t.Run(profile.ID, func(t *testing.T) {
			spec, err := Spec(profile.ID)
			if err != nil {
				t.Fatal(err)
			}
			native := false
			for _, ext := range spec.Extensions {
				if share, ok := ext.(*u.KeyShareExtension); ok {
					for _, key := range share.KeyShares {
						if key.Group == u.X25519 {
							native = true
						}
					}
				}
				if generic, ok := ext.(*u.GenericExtension); ok && generic.Id == 0xca34 {
					t.Fatal("trust_anchors appeared in a pre-149 profile")
				}
			}
			if !native {
				t.Fatal("no native X25519 share for REALITY")
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			conn := u.UClient(a, &u.Config{ServerName: "example.com", InsecureSkipVerify: true}, u.HelloCustom)
			if err := conn.ApplyPreset(&spec); err != nil {
				t.Fatal(err)
			}
			if err := conn.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			if err := conn.MarshalClientHello(); err != nil {
				t.Fatal(err)
			}
			if len(conn.HandshakeState.Hello.Raw) == 0 {
				t.Fatal("empty hello")
			}
		})
	}
}

func TestRandomBrowserChoiceStaysWithinRequestedFamily(t *testing.T) {
	for _, family := range []string{"chrome", "firefox", "browser"} {
		seen := map[string]bool{}
		for i := 0; i < 100; i++ {
			id, err := Resolve("random_" + family)
			if err != nil {
				t.Fatal(err)
			}
			allowed := false
			for _, p := range Profiles() {
				if p.ID == id && (family == "browser" || family == p.Family) {
					allowed = true
				}
			}
			if !allowed {
				t.Fatalf("%s selected %s", family, id)
			}
			seen[id] = true
		}
		if len(seen) < 2 {
			t.Fatalf("%s did not vary", family)
		}
	}
	for _, bad := range []string{"chrome_999", "random_unknown"} {
		if _, err := Spec(bad); err == nil {
			t.Fatal("unknown profile accepted", bad)
		}
	}
}
