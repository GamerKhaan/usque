package internal

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func testSOCKSServer(t *testing.T) *SOCKS5Server {
	t.Helper()
	dial := (&net.Dialer{}).DialContext
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: "127.0.0.1:0", DialTCP: dial, DialUDP: dial,
		DialTimeout: time.Second, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSOCKSDialTimeout(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var calls atomic.Int32
			blocked := func(ctx context.Context, _, _ string) (net.Conn, error) {
				calls.Add(1)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			s := testSOCKSServer(t)
			s.cfg.DialTimeout = 30 * time.Millisecond
			s.cfg.DialTCP, s.cfg.DialUDP = blocked, blocked
			start := time.Now()
			var err error
			if network == "tcp" {
				_, err = s.dialTCP(network, "", "example.invalid:443")
			} else {
				_, err = s.dialUDP(network, "", "example.invalid:53")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("got %v, want deadline exceeded", err)
			}
			if elapsed := time.Since(start); elapsed < 20*time.Millisecond || elapsed > time.Second {
				t.Fatalf("timeout elapsed %v", elapsed)
			}
			if calls.Load() != 1 {
				t.Fatalf("dial calls = %d", calls.Load())
			}
		})
	}
}

func TestSOCKSDialCancelsSuccessfulContext(t *testing.T) {
	s := testSOCKSServer(t)
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	var dialCtx context.Context
	s.cfg.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialCtx = ctx
		return a, nil
	}
	c, err := s.dialTCP("tcp", "", "example.invalid:443")
	if err != nil || c != a || dialCtx.Err() != context.Canceled {
		t.Fatalf("connection=%v error=%v context error=%v", c, err, dialCtx.Err())
	}
}

func blackholeNetstack(t *testing.T) *netstack.Net {
	t.Helper()
	dev, n, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.2")}, []netip.Addr{netip.MustParseAddr("192.0.2.53")}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffers, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			if _, err := dev.Read(buffers, sizes, 0); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = dev.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("netstack reader did not stop")
		}
	})
	return n
}

func TestSOCKSTunnelTCPAndDNSAreBounded(t *testing.T) {
	n := blackholeNetstack(t)
	s, err := NewSOCKS5Server(SOCKS5Config{
		Addr: "127.0.0.1:0", TunNet: n, Resolver: &TunnelDNSResolver{TunNet: n}, DialTimeout: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ network, target string }{
		{"tcp", "192.0.2.3:443"}, {"tcp", "test.invalid:443"}, {"udp", "test.invalid:53"},
	} {
		t.Run(tc.network+"/"+tc.target, func(t *testing.T) {
			start := time.Now()
			var err error
			if tc.network == "tcp" {
				_, err = s.dialTCP("tcp", "", tc.target)
			} else {
				_, err = s.dialUDP("udp", "", tc.target)
			}
			if err == nil {
				t.Fatal("blackhole unexpectedly connected")
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("expected timeout, got %T: %v", err, err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("dial took %v", elapsed)
			}
		})
	}
}

func TestTunnelDNSResolverCancellation(t *testing.T) {
	r := TunnelDNSResolver{TunNet: blackholeNetstack(t), DNSAddrs: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Resolve(ctx, "test.invalid")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("DNS error=%v elapsed=%v", err, time.Since(start))
	}
}

func TestSOCKSStartReportsBindFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	s := testSOCKSServer(t)
	s.server.Addr = l.Addr().String()
	if err := s.Start(); err == nil {
		t.Fatal("occupied listen address did not fail startup")
	}
}

func zeroAssociate(ipv6 bool) *socks5.Request {
	atyp, addr := byte(socks5.ATYPIPv4), net.IPv4zero.To4()
	if ipv6 {
		atyp, addr = socks5.ATYPIPv6, net.IPv6zero
	}
	return &socks5.Request{Cmd: socks5.CmdUDP, Atyp: atyp, DstAddr: addr, DstPort: []byte{0, 0}}
}

func TestZeroAssociateValidation(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		r := zeroAssociate(ipv6)
		if !isZeroUDPAssociateRequest(r) {
			t.Fatal("zero source not recognized")
		}
		r.DstPort = []byte{1, 2}
		if isZeroUDPAssociateRequest(r) {
			t.Fatal("explicit port treated as wildcard")
		}
	}
	for _, r := range []*socks5.Request{
		{Atyp: socks5.ATYPDomain, DstAddr: []byte{1, 'x'}, DstPort: []byte{0, 0}},
		{Atyp: socks5.ATYPIPv4, DstAddr: []byte{127, 0, 0, 1}, DstPort: []byte{0, 0}},
		{Atyp: socks5.ATYPIPv4, DstAddr: []byte{0, 0, 0, 0}, DstPort: []byte{0}},
	} {
		if isZeroUDPAssociateRequest(r) {
			t.Fatal("nonzero or invalid source treated as wildcard")
		}
	}
}

func TestZeroAssociateConcurrentClaim(t *testing.T) {
	s := testSOCKSServer(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	first, err := s.registerUDPAssociation(zeroAssociate(false), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeUDPAssociation(first)
	second, err := s.registerUDPAssociation(zeroAssociate(false), peer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeUDPAssociation(second)
	addr := &net.UDPAddr{IP: peer.IP, Port: 4321}
	var wg sync.WaitGroup
	for range 128 {
		wg.Go(func() {
			a, ok := s.claimUDPAssociation(addr)
			if !ok || a != first {
				t.Errorf("concurrent datagram claimed %p, wanted %p", a, first)
			}
		})
	}
	wg.Wait()
	if len(s.pendingUDP[peer.IP.String()]) != 1 || second.source != "" {
		t.Fatal("same-source burst consumed second pending association")
	}
	if _, ok := s.claimUDPAssociation(&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 4321}); ok {
		t.Fatal("different IP claimed association")
	}
}

func TestZeroAssociateClaimCloseRace(t *testing.T) {
	s := testSOCKSServer(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	addr := &net.UDPAddr{IP: peer.IP, Port: 4321}
	for range 200 {
		a, err := s.registerUDPAssociation(zeroAssociate(false), peer)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() { s.claimUDPAssociation(addr) })
		wg.Go(func() { s.closeUDPAssociation(a) })
		wg.Wait()
		if len(s.pendingUDP) != 0 || len(s.associatedUDP) != 0 || a.ctx.Err() == nil {
			t.Fatal("closed association was republished or left pending")
		}
	}
}

func TestExplicitUDPAssociationRemainsStrict(t *testing.T) {
	s := testSOCKSServer(t)
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	r := &socks5.Request{Atyp: socks5.ATYPIPv4, DstAddr: peer.IP.To4(), DstPort: []byte{0x10, 0x00}}
	a, err := s.registerUDPAssociation(r, peer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.closeUDPAssociation(a)
	if _, ok := s.claimUDPAssociation(&net.UDPAddr{IP: peer.IP, Port: 4097}); ok {
		t.Fatal("explicit port was not enforced")
	}
	if _, ok := s.claimUDPAssociation(&net.UDPAddr{IP: peer.IP, Port: 4096}); !ok {
		t.Fatal("explicit source rejected")
	}
	if _, err := s.registerUDPAssociation(r, peer); err == nil {
		t.Fatal("duplicate explicit source replaced live association")
	}
	r.DstAddr = []byte{192, 0, 2, 11}
	if _, err := s.registerUDPAssociation(r, peer); err == nil {
		t.Fatal("foreign IP accepted")
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server.(*net.TCPConn), client
}

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestUDPAssociateRoundTripBurstAndCleanup(t *testing.T) {
	s := testSOCKSServer(t)
	// Disable idle timeout: closing the TCP association must still stop its UDP readers.
	s.cfg.UDPTimeout = 0
	s.server.UDPConn = udpSocket(t)
	remote, udpClient := udpSocket(t), udpSocket(t)
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 65535)
		for {
			n, peer, err := remote.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := remote.WriteToUDP(buf[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = remote.Close()
		select {
		case <-echoDone:
		case <-time.After(time.Second):
			t.Error("UDP echo reader leaked")
		}
	})
	serverConn, control := tcpPair(t)
	controlDone := make(chan error, 1)
	go func() { controlDone <- s.TCPHandle(s.server, serverConn, zeroAssociate(false)) }()
	if err := control.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reply, err := socks5.NewReplyFrom(control)
	if err != nil || reply.Rep != socks5.RepSuccess {
		t.Fatalf("UDP ASSOCIATE reply=%v error=%v", reply, err)
	}
	if int(binary.BigEndian.Uint16(reply.BndPort)) != s.server.UDPConn.LocalAddr().(*net.UDPAddr).Port {
		t.Fatal("reply does not advertise actual UDP port")
	}
	var dialCount atomic.Int32
	s.cfg.DialUDP = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCount.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(remote.LocalAddr().(*net.UDPAddr).Port))
	d := socks5.NewDatagram(socks5.ATYPIPv4, net.IPv4(127, 0, 0, 1).To4(), port, []byte("payload"))
	const packets = 24
	var wg sync.WaitGroup
	for range packets {
		wg.Go(func() {
			if err := s.UDPHandle(s.server, udpClient.LocalAddr().(*net.UDPAddr), d); err != nil {
				t.Errorf("UDP burst failed: %v", err)
			}
		})
	}
	wg.Wait()
	if err := udpClient.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for range packets {
		buf := make([]byte, 1024)
		n, _, err := udpClient.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		got, err := socks5.NewDatagramFromBytes(buf[:n])
		if err != nil || string(got.Data) != "payload" {
			t.Fatalf("UDP response=%v error=%v", got, err)
		}
	}
	if dialCount.Load() != 1 {
		t.Fatalf("burst created %d relays for one flow", dialCount.Load())
	}
	_ = control.Close()
	select {
	case err := <-controlDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP association handler did not stop")
	}
	deadline := time.Now().Add(time.Second)
	for {
		count := 0
		s.udpFlows.Range(func(_, _ any) bool { count++; return true })
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP relay reader survived control closure with idle timeout disabled")
		}
		time.Sleep(time.Millisecond)
	}
	if err := s.UDPHandle(s.server, udpClient.LocalAddr().(*net.UDPAddr), d); err == nil {
		t.Fatal("datagram accepted after control connection closed")
	}
}

func TestUDPQueuedDialsCancelWithAssociation(t *testing.T) {
	s := testSOCKSServer(t)
	s.cfg.DialTimeout = 2 * time.Second
	peer := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	a, err := s.registerUDPAssociation(zeroAssociate(false), peer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.closeUDPAssociation(a) })
	addr := &net.UDPAddr{IP: peer.IP, Port: 4321}
	if _, ok := s.claimUDPAssociation(addr); !ok {
		t.Fatal("failed to claim association")
	}
	var calls atomic.Int32
	dialStarted := make(chan struct{}, 1)
	abort := make(chan struct{})
	s.cfg.DialUDP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		select {
		case dialStarted <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-abort:
			return nil, context.Canceled
		}
	}
	const packets = 64
	done := make(chan error, packets)
	var wg sync.WaitGroup
	t.Cleanup(func() { close(abort); wg.Wait() })
	d := socks5.NewDatagram(socks5.ATYPDomain, []byte("blackhole.invalid"), []byte{0, 53}, []byte("payload"))
	for range packets {
		wg.Go(func() { done <- s.UDPHandle(s.server, addr, d) })
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP setup did not start")
	}
	s.closeUDPAssociation(a)
	deadline := time.After(500 * time.Millisecond)
	for range packets {
		select {
		case err := <-done:
			if err == nil {
				t.Error("closed association accepted a datagram")
			}
		case <-deadline:
			t.Fatal("in-flight or queued UDP setup outlived association cancellation")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("queued packets started %d dials after cancellation", calls.Load())
	}
}
