package internal

import "github.com/txthinking/socks5"

// socksUDPParseFailureReason describes the pinned parser's rejection using only
// frame length, ATYP and the optional domain-length byte. It never reads the
// destination address, domain, port or application payload. This is diagnostic
// only: NewDatagramFromBytes remains responsible for accepting each datagram.
func socksUDPParseFailureReason(frame []byte) string {
	if len(frame) < 4 {
		return "short_header"
	}
	var addressEnd int
	switch frame[3] {
	case socks5.ATYPIPv4:
		addressEnd = 8
	case socks5.ATYPIPv6:
		addressEnd = 20
	case socks5.ATYPDomain:
		if len(frame) < 5 {
			return "truncated_address"
		}
		if frame[4] == 0 {
			return "zero_domain_length"
		}
		addressEnd = 5 + int(frame[4])
	default:
		return "invalid_atyp"
	}
	if len(frame) < addressEnd {
		return "truncated_address"
	}
	if len(frame) < addressEnd+2 {
		return "missing_port"
	}
	if len(frame) == addressEnd+2 {
		// The dependency rejects header-only frames, even with a complete port.
		return "empty_payload"
	}
	// Retain an explicit fallback if a future dependency adds a rejection rule.
	return "unclassified"
}
