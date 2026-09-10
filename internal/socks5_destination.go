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
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
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
