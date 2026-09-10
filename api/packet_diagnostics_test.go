package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
)

func diagnosticIPv4(source string, protocol byte, payload []byte) []byte {
	p := make([]byte, 20+len(payload))
	p[0], p[8], p[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], netip.MustParseAddr(source).AsSlice())
	copy(p[16:20], []byte{192, 0, 2, 2})
	copy(p[20:], payload)
	return p
}

func TestClassifyLoopbackPacket(t *testing.T) {
	icmp := diagnosticIPv4("127.0.0.1", 1, []byte{3, 4, 0, 0})
	withOptions := append(append(append([]byte{}, icmp[:20]...), make([]byte, 4)...), icmp[20:]...)
	withOptions[0] = 0x46
	binary.BigEndian.PutUint16(withOptions[2:4], uint16(len(withOptions)))
	fragment := append([]byte{}, icmp...)
	fragment[7] = 1
	v6 := make([]byte, 42)
	v6[0], v6[6], v6[40], v6[41] = 0x60, 58, 2, 0
	binary.BigEndian.PutUint16(v6[4:6], 2)
	copy(v6[8:24], netip.IPv6Loopback().AsSlice())
	mapped := append([]byte{}, v6...)
	copy(mapped[8:24], netip.MustParseAddr("::ffff:127.0.0.2").AsSlice())
	extension := append([]byte{}, v6...)
	extension[6] = 0
	for _, tc := range []struct {
		name   string
		packet []byte
		want   loopbackPacketHeader
	}{
		{"IPv4 ICMP", icmp, loopbackPacketHeader{version: 4, protocol: 1, hasICMP: true, icmpType: 3, icmpCode: 4}},
		{"IPv4 options", withOptions, loopbackPacketHeader{version: 4, protocol: 1, hasICMP: true, icmpType: 3, icmpCode: 4}},
		{"IPv4 later fragment", fragment, loopbackPacketHeader{version: 4, protocol: 1}},
		{"IPv4 TCP", diagnosticIPv4("127.2.3.4", 6, nil), loopbackPacketHeader{version: 4, protocol: 6}},
		{"short ICMP", diagnosticIPv4("127.0.0.1", 1, []byte{3}), loopbackPacketHeader{version: 4, protocol: 1}},
		{"IPv6 ICMP", v6, loopbackPacketHeader{version: 6, protocol: 58, hasICMP: true, icmpType: 2}},
		{"IPv4 mapped", mapped, loopbackPacketHeader{version: 6, protocol: 58, hasICMP: true, icmpType: 2}},
		{"IPv6 extension", extension, loopbackPacketHeader{version: 6, protocol: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte{}, tc.packet...)
			got, ok := classifyLoopbackPacket(tc.packet)
			if !ok || got != tc.want {
				t.Fatalf("header = %+v, ok = %v; want %+v", got, ok, tc.want)
			}
			if !bytes.Equal(before, tc.packet) {
				t.Fatal("diagnostic modified the packet")
			}
		})
	}
}

func TestClassifyLoopbackPacketRejectsUnrelatedAndTruncatedHeaders(t *testing.T) {
	p := diagnosticIPv4("127.0.0.1", 1, []byte{3, 4})
	for length := 0; length < len(p); length++ {
		if _, ok := classifyLoopbackPacket(p[:length]); ok {
			t.Fatalf("accepted truncated IPv4 packet length %d", length)
		}
	}
	for _, source := range []string{"192.0.2.1", "10.0.0.1", "0.0.0.0"} {
		if _, ok := classifyLoopbackPacket(diagnosticIPv4(source, 1, []byte{3, 4})); ok {
			t.Fatalf("classified non-loopback source %s", source)
		}
	}
	for _, firstByte := range []byte{0, 0x44, 0x4f, 0x70} {
		p[0] = firstByte
		if _, ok := classifyLoopbackPacket(p); ok {
			t.Fatalf("accepted invalid header byte %x", firstByte)
		}
	}
	v6 := make([]byte, 42)
	v6[0], v6[6] = 0x60, 58
	binary.BigEndian.PutUint16(v6[4:6], 2)
	copy(v6[8:24], netip.IPv6Loopback().AsSlice())
	for length := 0; length < len(v6); length++ {
		if _, ok := classifyLoopbackPacket(v6[:length]); ok {
			t.Fatalf("accepted truncated IPv6 packet length %d", length)
		}
	}
}

func TestLoopbackPacketDiagnosticsRateLimitAndPrivacy(t *testing.T) {
	now := time.Unix(100, 0)
	var mu sync.Mutex
	var lines []string
	o := loopbackPacketObserver{
		now: func() time.Time { return now },
		logf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	packet := diagnosticIPv4("127.23.45.67", 1, append([]byte{3, 4}, []byte("secret-payload.example")...))
	before := append([]byte{}, packet...)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { o.observe(packetTunnelIngress, packet) })
	}
	wg.Wait()
	if len(lines) != 1 || !strings.Contains(lines[0], "origin=tunnel_ingress") || !strings.Contains(lines[0], "total=1") {
		t.Fatalf("first interval lines = %v", lines)
	}
	o.observe(packetLocalICMP, packet)
	o.observe(packetTunnelIngress, diagnosticIPv4("127.0.0.1", 6, nil))
	if len(lines) != 3 {
		t.Fatalf("origins and protocols did not receive independent counters: %v", lines)
	}
	now = now.Add(30 * time.Second)
	o.observe(packetTunnelIngress, packet)
	if len(lines) != 4 || !strings.Contains(lines[3], "total=101") || !strings.Contains(lines[3], "icmp_type=3 icmp_code=4") {
		t.Fatalf("next interval lines = %v", lines)
	}
	o.observe(packetTunnelIngress, diagnosticIPv4("192.0.2.1", 1, []byte{3, 4}))
	o.observe(packetOrigin(255), packet)
	if len(lines) != 4 || !bytes.Equal(packet, before) {
		t.Fatal("unrelated packets emitted or observed packet changed")
	}
	for _, line := range lines {
		for _, private := range []string{"secret-payload", ".example", "127.23.45.67", "192.0.2.2"} {
			if strings.Contains(line, private) {
				t.Fatalf("diagnostic disclosed packet content: %s", line)
			}
		}
	}
}

func diagnosticQuote(destination string) []byte {
	quote := diagnosticIPv4("192.0.2.2", 6, []byte("private application payload"))
	copy(quote[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(quote[10:12], ^checksum.Checksum(quote[:20], 0))
	return quote
}

func TestICMPQuotedDestinationClass(t *testing.T) {
	for _, tc := range []struct{ destination, class string }{
		{"127.0.0.1", "loopback"}, {"0.0.0.0", "unspecified"}, {"10.1.2.3", "private"},
		{"169.254.1.2", "link_local"}, {"224.0.0.1", "multicast"}, {"1.1.1.1", "global_unicast"}, {"255.255.255.255", "other"},
	} {
		for _, icmpType := range []byte{3, 11} {
			// A quote may contain only the original header and eight payload bytes,
			// even when the original IPv4 total length is larger.
			quote := diagnosticQuote(tc.destination)[:28]
			body := append([]byte{icmpType, 1, 0, 0, 0, 0, 0, 0}, quote...)
			packet := diagnosticIPv4("127.23.45.67", 1, body)
			before := append([]byte{}, packet...)
			header, ok := classifyLoopbackPacket(packet)
			if !ok || header.quotedDestination != tc.class {
				t.Fatalf("ICMP type %d quote destination %s: header=%+v ok=%v", icmpType, tc.destination, header, ok)
			}
			var line string
			o := loopbackPacketObserver{logf: func(format string, args ...any) { line = fmt.Sprintf(format, args...) }}
			o.observe(packetTunnelIngress, packet)
			if !strings.Contains(line, "quoted_destination_class="+tc.class) {
				t.Fatalf("missing quote class in diagnostic: %s", line)
			}
			for _, value := range []string{tc.destination, "127.23.45.67", "192.0.2.2", "private application"} {
				if strings.Contains(line, value) {
					t.Fatalf("quote leaked into diagnostic: %s", line)
				}
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("diagnostic modified ICMP quote")
			}
		}
	}
}

func TestICMPQuotedDestinationRequiresValidHeader(t *testing.T) {
	quote := diagnosticQuote("127.0.0.1")
	for size := 0; size < 20; size++ {
		if got := quotedIPv4DestinationClass(quote[:size]); got != "" {
			t.Fatalf("truncated quote size %d class = %s", size, got)
		}
	}
	for _, mutate := range []func([]byte){
		func(p []byte) { p[0] = 0x65 },
		func(p []byte) { p[0] = 0x44 },
		func(p []byte) { p[0] = 0x4f },
		func(p []byte) { p[10] ^= 1 },
		func(p []byte) { p[2], p[3] = 0, 19 },
	} {
		invalid := append([]byte{}, quote...)
		mutate(invalid)
		if got := quotedIPv4DestinationClass(invalid); got != "" {
			t.Fatalf("malformed quote classified as %s", got)
		}
	}
	for _, icmpType := range []byte{0, 4, 5, 8, 12} {
		body := append([]byte{icmpType, 0, 0, 0, 0, 0, 0, 0}, quote...)
		header, _ := classifyLoopbackPacket(diagnosticIPv4("127.0.0.1", 1, body))
		if header.quotedDestination != "" {
			t.Fatalf("unrelated ICMP type %d interpreted as quoted error", icmpType)
		}
	}
}
