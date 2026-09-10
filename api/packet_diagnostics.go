package api

import (
	"encoding/binary"
	"log"
	"net/netip"
	"time"
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
	version, protocol  byte
	icmpType, icmpCode byte
	hasICMP            bool
}

// classifyLoopbackPacket reads only the outer IP header and, when directly
// available, the ICMP type and code. It neither retains nor modifies packet data.
// IPv6 protocol is the outer next-header value; extension headers are not walked.
func classifyLoopbackPacket(packet []byte) (loopbackPacketHeader, bool) {
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
		h.protocol = packet[6]
		h.hasICMP = h.protocol == 58
	default:
		return h, false
	}
	if h.hasICMP && len(packet)-payloadOffset >= 2 {
		h.icmpType, h.icmpCode = packet[payloadOffset], packet[payloadOffset+1]
	} else {
		h.hasICMP = false
	}
	return h, true
}

// loopbackPacketObserver distinguishes locally synthesized ICMP from packets
// received through the tunnel. Bounded counters are separate for each origin and
// outer IP protocol; each emits at most once per 30 seconds after its first event.
// This does not change the netstack's packet validation or forwarding behavior.
type loopbackPacketObserver struct {
	counters [2][256]packetErrorObserver
	now      func() time.Time
	logf     func(string, ...any)
}

func (o *loopbackPacketObserver) observe(origin packetOrigin, packet []byte) {
	if origin > packetTunnelIngress {
		return
	}
	h, ok := classifyLoopbackPacket(packet)
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
	if h.hasICMP {
		logf("Tunnel packet diagnostic: origin=%s source_class=loopback ip_version=%d protocol=%d icmp_type=%d icmp_code=%d total=%d; packet passed unchanged to netstack validation", origin, h.version, h.protocol, h.icmpType, h.icmpCode, total)
	} else {
		logf("Tunnel packet diagnostic: origin=%s source_class=loopback ip_version=%d protocol=%d total=%d; packet passed unchanged to netstack validation", origin, h.version, h.protocol, total)
	}
}
