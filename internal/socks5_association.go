package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/txthinking/socks5"
)

// source and peerIP are protected by SOCKS5Server.udpAssociationMu. The same
// lock covers lookup, first-datagram claim, publication and removal, so a burst
// cannot consume multiple pending associations or publish one after closure.
type udpAssociation struct {
	source string
	peerIP string
	ctx    context.Context
	cancel context.CancelFunc
}

func isZeroUDPAssociateRequest(r *socks5.Request) bool {
	if len(r.DstPort) != 2 || binary.BigEndian.Uint16(r.DstPort) != 0 {
		return false
	}
	switch r.Atyp {
	case socks5.ATYPIPv4, socks5.ATYPIPv6:
		return net.IP(r.DstAddr).IsUnspecified()
	default:
		return false
	}
}

func (s *SOCKS5Server) registerUDPAssociation(r *socks5.Request, peer net.Addr) (*udpAssociation, error) {
	peerHost, peerPort, err := net.SplitHostPort(peer.String())
	if err != nil {
		return nil, err
	}
	peerIP := net.ParseIP(peerHost)
	if peerIP == nil || len(r.DstPort) != 2 {
		return nil, socks5.ErrBadRequest
	}
	source := ""
	if !isZeroUDPAssociateRequest(r) {
		ip := net.IP(r.DstAddr)
		if r.Atyp == socks5.ATYPDomain {
			if len(r.DstAddr) < 2 {
				return nil, socks5.ErrBadRequest
			}
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
			ips, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip", string(r.DstAddr[1:]))
			cancel()
			if lookupErr != nil {
				return nil, lookupErr
			}
			ip = nil
			for _, candidate := range ips {
				if candidate.Equal(peerIP) {
					ip = candidate
					break
				}
			}
		}
		if ip.IsUnspecified() {
			ip = peerIP
		}
		// RFC 1928 requires rejecting UDP from an IP other than the TCP peer.
		if !ip.Equal(peerIP) {
			return nil, fmt.Errorf("UDP ASSOCIATE source must match TCP peer IP")
		}
		port := binary.BigEndian.Uint16(r.DstPort)
		if port == 0 {
			source = net.JoinHostPort(ip.String(), peerPort)
		} else {
			source = net.JoinHostPort(ip.String(), fmt.Sprint(port))
		}
	}

	s.udpAssociationMu.Lock()
	defer s.udpAssociationMu.Unlock()
	if source != "" && s.associatedUDP[source] != nil {
		return nil, fmt.Errorf("UDP source already has a live TCP association")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &udpAssociation{source: source, peerIP: peerIP.String(), ctx: ctx, cancel: cancel}
	if source == "" {
		s.pendingUDP[a.peerIP] = append(s.pendingUDP[a.peerIP], a)
	} else {
		s.associatedUDP[source] = a
	}
	return a, nil
}

func (s *SOCKS5Server) claimUDPAssociation(addr *net.UDPAddr) (*udpAssociation, bool) {
	s.udpAssociationMu.Lock()
	defer s.udpAssociationMu.Unlock()
	source, ip := addr.String(), addr.IP.String()
	if a := s.associatedUDP[source]; a != nil {
		return a, a.ctx.Err() == nil
	}
	pending := s.pendingUDP[ip]
	if len(pending) == 0 {
		return nil, false
	}
	a := pending[0]
	if len(pending) == 1 {
		delete(s.pendingUDP, ip)
	} else {
		pending[0] = nil
		s.pendingUDP[ip] = pending[1:]
	}
	a.source = source
	s.associatedUDP[source] = a
	return a, true
}

func (s *SOCKS5Server) closeUDPAssociation(a *udpAssociation) {
	s.udpAssociationMu.Lock()
	defer s.udpAssociationMu.Unlock()
	a.cancel()
	if a.source != "" {
		if s.associatedUDP[a.source] == a {
			delete(s.associatedUDP, a.source)
		}
		return
	}
	pending := s.pendingUDP[a.peerIP]
	for i, candidate := range pending {
		if candidate == a {
			copy(pending[i:], pending[i+1:])
			pending[len(pending)-1] = nil
			pending = pending[:len(pending)-1]
			break
		}
	}
	if len(pending) == 0 {
		delete(s.pendingUDP, a.peerIP)
	} else {
		s.pendingUDP[a.peerIP] = pending
	}
}
