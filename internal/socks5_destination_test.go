package internal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestTunnelDestinationClasses(t *testing.T) {
	for _, host := range []string{
		"0.0.0.0", "127.0.0.1", "127.255.255.254", "::", "::1", "::1%lo",
		"::ffff:0.0.0.0", "::ffff:127.0.0.1", "localhost", "LOCALHOST.", "service.localhost.",
	} {
		if err := validateTunnelDestinationHost(host); !errors.Is(err, ErrInvalidTunnelDestination) {
			t.Errorf("local-only host %q error = %v", host, err)
		}
	}
	for _, host := range []string{
		"1.1.1.1", "192.0.2.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1",
		"2606:4700:4700::1111", "fd00::1", "::ffff:192.0.2.1", "example.com", "localhost.example.com",
	} {
		if err := validateTunnelDestinationHost(host); err != nil {
			t.Errorf("other host %q rejected: %v", host, err)
		}
	}
}

func TestTunnelDestinationRejectsBeforeNetstackTraffic(t *testing.T) {
	dev, n, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::2")},
		[]netip.Addr{netip.MustParseAddr("192.0.2.53")}, 1280,
	)
	if err != nil {
		t.Fatal(err)
	}
	var packets atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffers, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			if _, err := dev.Read(buffers, sizes, 0); err != nil {
				return
			}
			packets.Add(1)
		}
	}()
	t.Cleanup(func() {
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("netstack packet reader did not stop")
		}
	})
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: "127.0.0.1:0", TunNet: n, Resolver: &TunnelDNSResolver{TunNet: n}, DialTimeout: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, host := range []string{"0.0.0.0", "127.0.0.1", "::", "::1", "::ffff:127.0.0.1", "::ffff:0.0.0.0", "localhost", "proxy.LOCALHOST."} {
			t.Run(network+"/"+host, func(t *testing.T) {
				target := net.JoinHostPort(host, "9")
				var c net.Conn
				var err error
				if network == "tcp" {
					c, err = s.dialTCP(network, "", target)
				} else {
					c, err = s.dialUDP(network, "", target)
				}
				if c != nil {
					_ = c.Close()
				}
				if c != nil || !errors.Is(err, ErrInvalidTunnelDestination) {
					t.Fatalf("dial returned connection %v, error %v", c, err)
				}
			})
		}
	}
	if got := packets.Load(); got != 0 {
		t.Fatalf("rejected requests emitted %d tunnel packets", got)
	}
	serverConn, client := tcpPair(t)
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	replyDone := make(chan error, 1)
	go func() {
		_, err := s.connectTCP(serverConn, &socks5.Request{Cmd: socks5.CmdConnect, Atyp: socks5.ATYPIPv4, DstAddr: []byte{0, 0, 0, 0}, DstPort: []byte{0, 9}})
		replyDone <- err
	}()
	reply, err := socks5.NewReplyFrom(client)
	if err != nil || reply.Rep != socks5.RepNotAllowed {
		t.Fatalf("invalid destination reply = %v, error = %v", reply, err)
	}
	if err := <-replyDone; !errors.Is(err, ErrInvalidTunnelDestination) {
		t.Fatalf("invalid destination protocol error = %v", err)
	}
	// The guard does not reject legitimate routed destinations. This deliberately
	// blackholed TCP target should send a SYN and expire at the ordinary deadline.
	if _, err := s.dialTCP("tcp", "", "192.0.2.3:443"); err == nil || errors.Is(err, ErrInvalidTunnelDestination) {
		t.Fatalf("routed target error = %v", err)
	}
	if packets.Load() == 0 {
		t.Fatal("valid routed target did not reach netstack")
	}
	// Zero-source UDP ASSOCIATE describes the client's socket, not its destination.
	a, err := s.registerUDPAssociation(zeroAssociate(false), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	if err != nil {
		t.Fatal(err)
	}
	s.closeUDPAssociation(a)
}

func TestLocalDNSResolvedTunnelDestinationGuard(t *testing.T) {
	dnsConn := udpSocket(t)
	var address atomic.Value
	address.Store([4]byte{0, 0, 0, 0})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := dnsConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			header, err := p.Start(buf[:n])
			if err != nil {
				t.Errorf("parse DNS header: %v", err)
				return
			}
			question, err := p.Question()
			if err != nil {
				t.Errorf("parse DNS question: %v", err)
				return
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			if err := builder.StartQuestions(); err != nil {
				t.Error(err)
				return
			}
			if err := builder.Question(question); err != nil {
				t.Error(err)
				return
			}
			if err := builder.StartAnswers(); err != nil {
				t.Error(err)
				return
			}
			if question.Type == dnsmessage.TypeA {
				if err := builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: address.Load().([4]byte)}); err != nil {
					t.Error(err)
					return
				}
			}
			response, err := builder.Finish()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := dnsConn.WriteToUDP(response, peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = dnsConn.Close(); <-done })
	// This test is intentionally not parallel: only its host resolver is replaced.
	oldResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dnsConn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = oldResolver })
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: "127.0.0.1:0", TunNet: blackholeNetstack(t),
		Resolver: &TunnelDNSResolver{UseOSResolver: true, Timeout: time.Second}, DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, answer := range [][4]byte{{0, 0, 0, 0}, {127, 0, 0, 1}} {
		address.Store(answer)
		for _, network := range []string{"tcp", "udp"} {
			var c net.Conn
			var err error
			if network == "tcp" {
				c, err = s.dialTCP(network, "", "sinkhole.invalid:443")
			} else {
				c, err = s.dialUDP(network, "", "sinkhole.invalid:443")
			}
			if c != nil {
				_ = c.Close()
			}
			if c != nil || !errors.Is(err, ErrInvalidTunnelDestination) {
				t.Fatalf("resolved %v over %s returned connection %v, error %v", answer, network, c, err)
			}
		}
	}
}

func TestTunnelDestinationGuardPreservesCustomDialers(t *testing.T) {
	s := testSOCKSServer(t)
	var calls int
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		calls++
		return nil, nil
	}
	s.cfg.DialTCP, s.cfg.DialUDP = dial, dial
	for _, target := range []string{"127.0.0.1:9", "0.0.0.0:9", "localhost:9"} {
		if _, err := s.dialTCP("tcp", "", target); err != nil {
			t.Fatal(err)
		}
		if _, err := s.dialUDP("udp", "", target); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 6 {
		t.Fatalf("custom dial calls = %d, want 6", calls)
	}
}
