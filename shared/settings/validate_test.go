package settings

import "testing"

func TestEndpointRejectsBadPortsAndSupportsIPv6(t *testing.T) {
	for _, value := range []string{"example.com:443", "[2001:db8::1]:443"} {
		if err := Endpoint(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"host", "host:0", "host:65536", "host:abc", ":443", "bad\nname:443", "2001:db8::1:443"} {
		if err := Endpoint(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestPaddingRangeFitsWireEncoding(t *testing.T) {
	for _, value := range [][2]int{{-1, 1000000}, {900, 1}, {1000000, 2000000}} {
		min, max := PaddingRange(value[0], value[1])
		if min < 0 || max > 65535 || min > max {
			t.Fatalf("invalid range %d..%d", min, max)
		}
	}
}

func TestProfileRequiresKeyAndUser(t *testing.T) {
	if err := Profile("host:443", "example.com", "key", "alice"); err != nil {
		t.Fatal(err)
	}
	if Profile("host:443", "example.com", "", "alice") == nil {
		t.Fatal("missing key accepted")
	}
	if Profile("host:443", "example.com", "key", "bad/user") == nil {
		t.Fatal("invalid user accepted")
	}
}
