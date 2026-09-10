package api

import (
	"encoding/binary"
	"log"
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

type packetOrigin uint8

const (
	packetLocalICMP packetOrigin = iota
	packetTunnelIngress
)

func (origin packetOrigin) String() string {
	if origin == packetLocalICMP {
		return "local_icmp"
	}
	return "tunnel_ingress"
}

type loopbackPacketHeader struct {
	version, protocol                                                byte
	icmpType, icmpCode                                               byte
	hasICMP                                                          bool
	quotedDestination                                                string
	outerDestinationLocal, quotedSourceLocal, quotedDestinationLocal localAddressMatch
}

type localAddressMatch uint8

const (
	localAddressUnknown localAddressMatch = iota
	localAddressNo
	localAddressYes
)

func (m localAddressMatch) String() string {
	switch m {
	case localAddressNo:
		return "false"
	case localAddressYes:
		return "true"
	default:
		return "unknown"
	}
}

func matchesTunnelLocal(addr netip.Addr, localAddresses []netip.Addr) localAddressMatch {
	if !addr.IsValid() {
		return localAddressUnknown
	}
	addr = addr.WithZone("").Unmap()
	match := localAddressUnknown
	for _, local := range localAddresses {
		if !local.IsValid() {
			continue
		}
		match = localAddressNo
		if local.WithZone("").Unmap() == addr {
			return localAddressYes
		}
	}
	return match
}

// classifyLoopbackPacket reads IP headers and, when directly available, ICMP type
// and code. It neither retains nor modifies packet data or reads application data.
// IPv6 protocol is the outer next-header value; extension headers are not walked.
func classifyLoopbackPacket(packet []byte, localAddresses ...netip.Addr) (loopbackPacketHeader, bool) {
	var h loopbackPacketHeader
	if len(packet) == 0 {
		return h, false
	}
	h.version = packet[0] >> 4
	var payloadOffset int
	switch h.version {
	case 4:
		if len(packet) < 20 {
			return h, false
		}
		payloadOffset = int(packet[0]&0xf) * 4
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if payloadOffset < 20 || payloadOffset > total || total > len(packet) {
			return h, false
		}
		if !netip.AddrFrom4([4]byte(packet[12:16])).IsLoopback() {
			return h, false
		}
		packet = packet[:total]
		h.outerDestinationLocal = matchesTunnelLocal(netip.AddrFrom4([4]byte(packet[16:20])), localAddresses)
		h.protocol = packet[9]
		// Later IPv4 fragments do not start with an ICMP header.
		h.hasICMP = h.protocol == 1 && binary.BigEndian.Uint16(packet[6:8])&0x1fff == 0
	case 6:
		if len(packet) < 40 {
			return h, false
		}
		total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if total > len(packet) || !netip.AddrFrom16([16]byte(packet[8:24])).Unmap().IsLoopback() {
			return h, false
		}
		packet = packet[:total]
		payloadOffset = 40
		h.outerDestinationLocal = matchesTunnelLocal(netip.AddrFrom16([16]byte(packet[24:40])), localAddresses)
		h.protocol = packet[6]
		h.hasICMP = h.protocol == 58
	default:
		return h, false
	}
	if h.hasICMP && len(packet)-payloadOffset >= 2 {
		h.icmpType, h.icmpCode = packet[payloadOffset], packet[payloadOffset+1]
		if h.version == 4 && (h.icmpType == 3 || h.icmpType == 11) && len(packet)-payloadOffset >= 8 {
			quote := packet[payloadOffset+8:]
			h.quotedDestination = quotedIPv4DestinationClass(quote)
			if h.quotedDestination != "" {
				h.quotedSourceLocal = matchesTunnelLocal(netip.AddrFrom4([4]byte(quote[12:16])), localAddresses)
				h.quotedDestinationLocal = matchesTunnelLocal(netip.AddrFrom4([4]byte(quote[16:20])), localAddresses)
			}
		}
	} else {
		h.hasICMP = false
	}
	return h, true
}

// ICMP errors quote only a prefix of the original packet. Require a complete,
// checksummed IPv4 header, but not its full original payload. Only the address
// class is returned; no quoted bytes or address values enter diagnostics.
func quotedIPv4DestinationClass(quote []byte) string {
	if len(quote) < 20 || quote[0]>>4 != 4 {
		return ""
	}
	headerLen := int(quote[0]&0xf) * 4
	if headerLen < 20 || headerLen > len(quote) || int(binary.BigEndian.Uint16(quote[2:4])) < headerLen || checksum.Checksum(quote[:headerLen], 0) != 0xffff {
		return ""
	}
	addr := netip.AddrFrom4([4]byte(quote[16:20]))
	switch {
	case addr.IsLoopback():
		return "loopback"
	case addr.IsUnspecified():
		return "unspecified"
	case addr.IsPrivate():
		return "private"
	case addr.IsLinkLocalUnicast():
		return "link_local"
	case addr.IsMulticast():
		return "multicast"
	case addr.IsGlobalUnicast():
		return "global_unicast"
	default:
		return "other"
	}
}

// loopbackPacketObserver distinguishes locally synthesized ICMP from packets
// received through the tunnel. Bounded counters are separate for each origin and
// outer IP protocol; each emits at most once per 30 seconds after its first event.
// This does not change the netstack's packet validation or forwarding behavior.
type loopbackPacketObserver struct {
	counters       [2][256]packetErrorObserver
	localAddresses []netip.Addr
	now            func() time.Time
	logf           func(string, ...any)
}

func (o *loopbackPacketObserver) observe(origin packetOrigin, packet []byte) {
	if origin > packetTunnelIngress {
		return
	}
	h, ok := classifyLoopbackPacket(packet, o.localAddresses...)
	if !ok {
		return
	}
	now := time.Now
	if o.now != nil {
		now = o.now
	}
	total, emit := o.counters[origin][h.protocol].record(now())
	if !emit {
		return
	}
	logf := log.Printf
	if o.logf != nil {
		logf = o.logf
	}
	if h.quotedDestination != "" {
		logf("Tunnel packet diagnostic: origin=%s source_class=loopback ip_version=%d protocol=%d outer_destination_is_tunnel_local=%s icmp_type=%d icmp_code=%d quoted_destination_class=%s quoted_src_is_tunnel_local=%s quoted_dst_is_tunnel_local=%s total=%d; packet passed unchanged to netstack validation", origin, h.version, h.protocol, h.outerDestinationLocal, h.icmpType, h.icmpCode, h.quotedDestination, h.quotedSourceLocal, h.quotedDestinationLocal, total)
	} else if h.hasICMP {
		logf("Tunnel packet diagnostic: origin=%s source_class=loopback ip_version=%d protocol=%d outer_destination_is_tunnel_local=%s icmp_type=%d icmp_code=%d total=%d; packet passed unchanged to netstack validation", origin, h.version, h.protocol, h.outerDestinationLocal, h.icmpType, h.icmpCode, total)
	} else {
		logf("Tunnel packet diagnostic: origin=%s source_class=loopback ip_version=%d protocol=%d outer_destination_is_tunnel_local=%s total=%d; packet passed unchanged to netstack validation", origin, h.version, h.protocol, h.outerDestinationLocal, total)
	}
}
