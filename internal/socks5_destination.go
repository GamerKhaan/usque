package internal

import (
	"errors"
	"net"
	"net/netip"
	"strings"
)

// ErrInvalidTunnelDestination identifies local-only destinations that cannot be
// reached through WARP. In particular, netstack rewrites unspecified destinations
// to loopback, causing otherwise avoidable remote errors and dial timeouts.
var ErrInvalidTunnelDestination = errors.New("loopback, unspecified and localhost destinations cannot be routed through the WARP tunnel")

func validateTunnelDestination(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	return validateTunnelDestinationHost(host)
}

func validateTunnelDestinationHost(host string) error {
	parseHost := host
	// Netstack strips the last IPv6 zone suffix before parsing, including an
	// empty suffix. Match that behavior so a scoped unspecified address cannot
	// evade the guard. The original destination remains unchanged for dialing.
	if strings.ContainsRune(parseHost, ':') {
		if zone := strings.LastIndexByte(parseHost, '%'); zone >= 0 {
			parseHost = parseHost[:zone]
		}
	}
	if ip, err := netip.ParseAddr(parseHost); err == nil {
		ip = ip.WithZone("").Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() {
			return ErrInvalidTunnelDestination
		}
		return nil
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return ErrInvalidTunnelDestination
	}
	return nil
}
