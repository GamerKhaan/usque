package internal

import (
	"testing"

	"github.com/txthinking/socks5"
)

func TestSOCKSUDPParseFailureReason(t *testing.T) {
	tests := []struct {
		name   string
		frame  []byte
		reason string
	}{
		{"empty", nil, "short_header"},
		{"short base", []byte{0, 0, 0}, "short_header"},
		{"unknown address type", []byte{0, 0, 0, 2}, "invalid_atyp"},
		{"short IPv4", []byte{0, 0, 0, 1, 192, 0, 2}, "truncated_address"},
		{"IPv4 missing port", []byte{0, 0, 0, 1, 192, 0, 2, 1}, "missing_port"},
		{"IPv4 short port", []byte{0, 0, 0, 1, 192, 0, 2, 1, 0}, "missing_port"},
		{"IPv4 empty payload", []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 53}, "empty_payload"},
		{"IPv4 accepted", []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 53, 1}, "unclassified"},
		{"IPv6 short address", []byte{0, 0, 0, 4}, "truncated_address"},
		{"domain length missing", []byte{0, 0, 0, 3}, "truncated_address"},
		{"domain length zero", []byte{0, 0, 0, 3, 0, 0, 53, 1}, "zero_domain_length"},
		{"domain short address", []byte{0, 0, 0, 3, 2, 'a'}, "truncated_address"},
		{"domain port missing", []byte{0, 0, 0, 3, 1, 'a'}, "missing_port"},
		{"domain empty payload", []byte{0, 0, 0, 3, 1, 'a', 0, 53}, "empty_payload"},
		{"domain accepted", []byte{0, 0, 0, 3, 1, 'a', 0, 53, 1}, "unclassified"},
		// The dependency accepts these; the caller separately drops fragments.
		{"fragment accepted by parser", []byte{0, 0, 1, 1, 192, 0, 2, 1, 0, 53, 1}, "unclassified"},
		{"RSV unchecked by parser", []byte{1, 2, 0, 1, 192, 0, 2, 1, 0, 53, 1}, "unclassified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := socksUDPParseFailureReason(tt.frame); got != tt.reason {
				t.Fatalf("reason = %q, want %q", got, tt.reason)
			}
			_, err := socks5.NewDatagramFromBytes(tt.frame)
			if rejected := tt.reason != "unclassified"; (err != nil) != rejected {
				t.Fatalf("pinned parser error = %v, diagnostic rejected = %t", err, rejected)
			}
		})
	}
}

func TestSOCKSUDPParseFailureReasonMatchesPinnedParser(t *testing.T) {
	// Exercise every ATYP and all frame-length boundaries, including the
	// maximum domain length. This catches drift when the parser is upgraded.
	for atyp := 0; atyp <= 255; atyp++ {
		for _, domainLength := range []byte{0, 1, 2, 127, 255} {
			frame := make([]byte, 280)
			frame[3] = byte(atyp)
			frame[4] = domainLength
			for size := 0; size <= len(frame); size++ {
				_, err := socks5.NewDatagramFromBytes(frame[:size])
				reason := socksUDPParseFailureReason(frame[:size])
				if (err != nil) != (reason != "unclassified") {
					t.Fatalf("ATYP %d domain length %d size %d: parser error %v, reason %q", atyp, domainLength, size, err, reason)
				}
			}
		}
	}
}
