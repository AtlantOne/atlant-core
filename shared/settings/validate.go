package settings

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func Endpoint(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
		return fmt.Errorf("server must be a host:port address (IPv6 in brackets)")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535")
	}
	return nil
}

func Profile(server, sni, key, user string) error {
	if err := Endpoint(server); err != nil {
		return err
	}
	if err := ServerName(sni); err != nil {
		return err
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("user key is required")
	}
	if len(user) < 1 || len(user) > 64 {
		return fmt.Errorf("user name must contain 1 to 64 characters")
	}
	for _, b := range []byte(user) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-') {
			return fmt.Errorf("user name contains unsupported characters")
		}
	}
	return nil
}

func ServerName(sni string) error {
	if len(sni) < 1 || len(sni) > 253 || strings.ContainsAny(sni, " \t\r\n/\\") {
		return fmt.Errorf("invalid server name")
	}
	return nil
}

// Padding is encoded as uint16 on wire. Larger values corrupt the next frame.
func PaddingRange(min, max int) (int, int) {
	if min < 0 {
		min = 0
	}
	if min > 65535 {
		min = 65535
	}
	if max < 0 {
		max = 0
	}
	if max > 65535 {
		max = 65535
	}
	if min > max {
		min, max = max, min
	}
	return min, max
}
