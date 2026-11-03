package atlant

func dnsViaQUIC(_ string, udpMode string, blocked bool) bool {
	return udpMode != "tcp" && !blocked
}
