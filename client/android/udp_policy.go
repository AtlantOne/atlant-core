package atlant

func dnsViaQUIC(tcpProto, udpMode string, blocked bool) bool {
	return (tcpProto == "quic" || tcpProto == "udp") && udpMode != "tcp" && !blocked
}
