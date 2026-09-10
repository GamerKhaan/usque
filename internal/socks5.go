package internal

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/txthinking/runnergroup"
	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// SOCKS5Config holds listen address, auth, tunnel dialers, and timeouts for [SOCKS5Server].
type SOCKS5Config struct {
	Addr        string
	Username    string
	Password    string
	Resolver    *TunnelDNSResolver
	TunNet      *netstack.Net
	DialTCP     func(ctx context.Context, network, address string) (net.Conn, error)
	DialUDP     func(ctx context.Context, network, address string) (net.Conn, error)
	TCPOnly     bool
	DialTimeout time.Duration // Bounds DNS resolution and connection establishment; 0 uses 15s.
	TCPTimeout  time.Duration // 0 = no deadline on TCP CONNECT relay
	UDPTimeout  time.Duration // 0 = no deadline on remote UDP reads
	Logger      *log.Logger
}

// SOCKS5Server wraps the SOCKS5 protocol parser with server-local dialers and associations.
type SOCKS5Server struct {
	cfg              SOCKS5Config
	server           *socks5.Server
	udpAssociationMu sync.Mutex
	pendingUDP       map[string][]*udpAssociation
	associatedUDP    map[string]*udpAssociation
	udpFlows         sync.Map // udpFlowKey -> *socks5.UDPExchange
	udpFlowLocks     [64]sync.Mutex
}

func NewSOCKS5Server(cfg SOCKS5Config) (*SOCKS5Server, error) {
	if cfg.DialTimeout < 0 {
		return nil, errors.New("socks5: DialTimeout must be positive")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if !cfg.TCPOnly && cfg.DialUDP == nil && (cfg.Resolver == nil || cfg.TunNet == nil) {
		return nil, errors.New("socks5: UDP needs DialUDP or a Resolver and TunNet")
	}
	if cfg.DialTCP == nil {
		if cfg.Resolver == nil {
			return nil, errors.New("socks5: Resolver is required")
		}
		if cfg.TunNet == nil {
			return nil, errors.New("socks5: TunNet is required")
		}
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	// BND.ADDR for UDP ASSOCIATE is set in TCPHandle via c.LocalAddr(), not here.
	srv, err := socks5.NewClassicServer(
		cfg.Addr,
		"",
		cfg.Username,
		cfg.Password,
		int(cfg.TCPTimeout/time.Second),
		int(cfg.UDPTimeout/time.Second),
	)
	if err != nil {
		return nil, err
	}

	s := &SOCKS5Server{
		cfg: cfg, server: srv,
		pendingUDP:    make(map[string][]*udpAssociation),
		associatedUDP: make(map[string]*udpAssociation),
	}
	if cfg.TCPOnly {
		srv.SupportedCommands = []byte{socks5.CmdConnect}
	}
	srv.LimitUDP = !cfg.TCPOnly
	return s, nil
}

// udpReadBufPool avoids allocating 64 KiB per SOCKS5 UDP datagram. The stock
// txthinking ListenAndServe uses make([]byte, 65507) every ReadFromUDP, which
// drives heap growth proportional to DHT/uTP packet rate (statviz stays high
// until a full GC cycle, and can look like a leak under load).
var udpReadBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65507)
		return &b
	},
}

// udpWireBufPool holds SOCKS5 UDP encapsulation frames for replies to the client.
// socks5.Datagram.Bytes() allocates a fresh slice every call; that dominated heap
// under uTP/DHT when multiplied by packet rate.
var udpWireBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 65507)
		return &b
	},
}

var tcpRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// Each SOCKS5 UDP datagram from the client is handled in a goroutine that must
// keep the pooled read buffer until UDPHandle returns. Without a bound, DHT/uTP
// packet rate creates unbounded concurrency and the pool grows one ~64 KiB buffer
// per in-flight handler (see heap: flat on udpReadBufPool.Get in listenAndServe).
const maxConcurrentUDPClientHandlers = 256

var udpClientHandleSem = make(chan struct{}, maxConcurrentUDPClientHandlers)

// Remote UDP relay goroutines (one per distinct client→dst flow) also pin a 64 KiB
// udpReadBufPool buffer. DHT opens many flows; cap relays so heap stays bounded.
const maxConcurrentUDPRelayHandlers = 256

var udpRelaySem = make(chan struct{}, maxConcurrentUDPRelayHandlers)

func (s *SOCKS5Server) Start() error {
	return s.listenAndServe()
}

// listenAndServe mirrors socks5.Server.ListenAndServe but the UDP relay uses
// udpReadBufPool. Datagrams reference the buffer until UDPHandle returns.
func (s *SOCKS5Server) listenAndServe() error {
	srv := s.server
	srv.Handle = socks5.Handler(s)

	addr, err := net.ResolveTCPAddr("tcp", srv.Addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	srv.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				c, err := l.AcceptTCP()
				if err != nil {
					return err
				}
				go func(c *net.TCPConn) {
					defer func() { _ = c.Close() }()
					if err := c.SetDeadline(time.Now().Add(s.cfg.DialTimeout)); err != nil {
						return
					}
					if err := srv.Negotiate(c); err != nil {
						logSOCKSError("negotiation", c.RemoteAddr(), err)
						return
					}
					r, err := srv.GetRequest(c)
					if err != nil {
						logSOCKSError("request parsing", c.RemoteAddr(), err)
						return
					}
					if err := c.SetDeadline(time.Time{}); err != nil {
						return
					}
					if err := srv.Handle.TCPHandle(srv, c, r); err != nil {
						log.Printf("SOCKS TCP handle from %s failed: %v", c.RemoteAddr(), err)
					}
				}(c)
			}
		},
		Stop: func() error {
			return l.Close()
		},
	})
	if s.cfg.TCPOnly {
		return srv.RunnerGroup.Wait()
	}

	// Share the actual TCP port, including when a library caller requests port 0.
	addr1, err := net.ResolveUDPAddr("udp", l.Addr().String())
	if err != nil {
		_ = l.Close()
		return err
	}
	srv.UDPConn, err = net.ListenUDP("udp", addr1)
	if err != nil {
		_ = l.Close()
		return err
	}
	srv.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				bp := udpReadBufPool.Get().(*[]byte)
				buf := *bp
				n, addr, err := srv.UDPConn.ReadFromUDP(buf)
				if err != nil {
					udpReadBufPool.Put(bp)
					return err
				}
				udpClientHandleSem <- struct{}{}
				go func(addr *net.UDPAddr, bp *[]byte, n int) {
					defer func() {
						udpReadBufPool.Put(bp)
						<-udpClientHandleSem
					}()
					payload := (*bp)[:n]
					d, err := socks5.NewDatagramFromBytes(payload)
					if err != nil {
						log.Println(err)
						return
					}
					if d.Frag != 0x00 {
						return
					}
					if err := srv.Handle.UDPHandle(srv, addr, d); err != nil {
						log.Println(err)
					}
				}(addr, bp, n)
			}
		},
		Stop: func() error {
			return srv.UDPConn.Close()
		},
	})
	return srv.RunnerGroup.Wait()
}

func logSOCKSError(stage string, addr net.Addr, err error) {
	if errors.Is(err, io.EOF) {
		log.Printf("SOCKS client %s closed during %s", addr, stage)
		return
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf("SOCKS client %s disconnected during %s: unexpected EOF", addr, stage)
		return
	}
	log.Printf("SOCKS client %s failed during %s: %v", addr, stage, err)
}

func (s *SOCKS5Server) dialTCP(network, _, raddr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	defer cancel()
	if s.cfg.DialTCP != nil {
		return s.cfg.DialTCP(ctx, network, raddr)
	}
	// Default (tunnel DNS): one netstack lookup + dial, same as the old things-go WithDial path.
	if s.cfg.Resolver.TunNet != nil {
		return s.cfg.TunNet.DialContext(ctx, network, raddr)
	}
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, err := net.ResolveTCPAddr(network, raddr)
		if err != nil {
			return nil, err
		}
		return s.cfg.TunNet.DialContextTCP(ctx, addr)
	}
	resIP, err := s.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveTCPAddr(network, net.JoinHostPort(resIP.String(), port))
	if err != nil {
		return nil, err
	}
	return s.cfg.TunNet.DialContextTCP(ctx, addr)
}

func (s *SOCKS5Server) dialUDP(network, laddr, raddr string) (net.Conn, error) {
	return s.dialUDPContext(context.Background(), network, laddr, raddr)
}

func (s *SOCKS5Server) dialUDPContext(parent context.Context, network, laddr, raddr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, s.cfg.DialTimeout)
	defer cancel()
	if s.cfg.DialUDP != nil {
		return s.cfg.DialUDP(ctx, network, raddr)
	}
	if s.cfg.Resolver.TunNet != nil {
		c, err := s.cfg.TunNet.DialContext(ctx, network, raddr)
		if err != nil {
			if strings.Contains(err.Error(), "port is in use") {
				return nil, &net.AddrError{Err: "address already in use", Addr: laddr}
			}
			return nil, err
		}
		return c, nil
	}
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, err := net.ResolveUDPAddr(network, raddr)
		if err != nil {
			return nil, err
		}
		return s.cfg.TunNet.DialContext(ctx, network, addr.String())
	}
	resIP, err := s.cfg.Resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(resIP.String(), port))
	if err != nil {
		return nil, err
	}
	rc, err := s.cfg.TunNet.DialContext(ctx, network, addr.String())
	if err != nil {
		if strings.Contains(err.Error(), "port is in use") {
			return nil, &net.AddrError{Err: "address already in use", Addr: laddr}
		}
		return nil, err
	}
	return rc, nil
}

func (s *SOCKS5Server) TCPHandle(srv *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	switch r.Cmd {
	case socks5.CmdConnect:
		rc, err := s.connectTCP(c, r)
		if err != nil {
			return err
		}
		defer func() { _ = rc.Close() }()
		s.relayTCP(c, rc, time.Duration(srv.TCPTimeout)*time.Second)
		return nil

	case socks5.CmdUDP:
		assoc, err := s.registerUDPAssociation(r, c.RemoteAddr())
		if err != nil {
			_, _ = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, net.IPv4zero.To4(), []byte{0, 0}).WriteTo(c)
			return err
		}
		defer s.closeUDPAssociation(assoc)
		// Publish before sending success: a client can send UDP as soon as it sees the reply.
		if err := c.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout)); err != nil {
			return err
		}
		replyAddr := &net.UDPAddr{IP: c.LocalAddr().(*net.TCPAddr).IP, Port: srv.UDPConn.LocalAddr().(*net.UDPAddr).Port}
		if err := writeSOCKSReply(c, replyAddr); err != nil {
			return err
		}
		if err := c.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, c)
		return nil
	}

	return socks5.ErrUnsupportCmd
}

func writeSOCKSReply(w io.Writer, addr net.Addr) error {
	atyp, host, port, err := socks5.ParseAddress(addr.String())
	if err != nil {
		return err
	}
	if atyp == socks5.ATYPDomain {
		host = host[1:]
	}
	_, err = socks5.NewReply(socks5.RepSuccess, atyp, host, port).WriteTo(w)
	return err
}

func (s *SOCKS5Server) connectTCP(c net.Conn, r *socks5.Request) (net.Conn, error) {
	if err := c.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout)); err != nil {
		return nil, err
	}
	defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	rc, err := s.dialTCP("tcp", "", r.Address())
	if err != nil {
		_, _ = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, net.IPv4zero.To4(), []byte{0, 0}).WriteTo(c)
		return nil, err
	}
	if err := writeSOCKSReply(c, rc.LocalAddr()); err != nil {
		_ = rc.Close()
		return nil, err
	}
	return rc, nil
}

type closeWriter interface {
	CloseWrite() error
}

func (s *SOCKS5Server) relayTCP(a, b net.Conn, timeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(dst, src net.Conn) {
		defer wg.Done()
		bp := tcpRelayBufPool.Get().(*[]byte)
		buf := *bp
		defer tcpRelayBufPool.Put(bp)
		for {
			if timeout > 0 {
				if err := src.SetReadDeadline(time.Now().Add(timeout)); err != nil {
					return
				}
			}
			n, err := src.Read(buf)
			if n > 0 {
				if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				if cw, ok := dst.(closeWriter); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}
	go relay(a, b)
	go relay(b, a)
	wg.Wait()
}

// UDPHandle is like txthinking DefaultHandle.UDPHandle but does not use srv.UDPSrc.
func (s *SOCKS5Server) UDPHandle(srv *socks5.Server, addr *net.UDPAddr, d *socks5.Datagram) error {
	src := addr.String()
	var assoc *udpAssociation
	var ch <-chan struct{}
	if srv.LimitUDP {
		var ok bool
		assoc, ok = s.claimUDPAssociation(addr)
		if !ok {
			return fmt.Errorf("udp address %s is not associated with tcp", src)
		}
		ch = assoc.ctx.Done()
	}
	send := func(ue *socks5.UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("udp address %s is not associated with tcp", src)
		default:
			if err := ue.RemoteConn.SetWriteDeadline(time.Now().Add(s.cfg.DialTimeout)); err != nil {
				return err
			}
			_, err := ue.RemoteConn.Write(data)
			return err
		}
	}

	dst := d.Address()
	key := udpFlowKey{source: src, destination: dst, association: assoc}
	// Serialize creation and sends for each flow, without holding the association lock during I/O.
	flowLock := s.udpFlowLock(src, dst)
	flowLock.Lock()
	defer flowLock.Unlock()
	dialCtx := context.Background()
	if assoc != nil {
		dialCtx = assoc.ctx
		// A queued packet may have claimed ownership before the TCP control
		// connection closed. Do not start another dial after it gets the lock.
		if err := dialCtx.Err(); err != nil {
			return err
		}
	}
	if iue, ok := s.udpFlows.Load(key); ok {
		return send(iue.(*socks5.UDPExchange), d.Data)
	}

	select {
	case udpRelaySem <- struct{}{}:
	default:
		return fmt.Errorf("too many active UDP relay exchanges")
	}

	rc, err := s.dialUDPContext(dialCtx, "udp", "", dst)
	if err != nil {
		<-udpRelaySem
		return err
	}
	ue := &socks5.UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	stopClose := func() bool { return true }
	if assoc != nil {
		stopClose = context.AfterFunc(assoc.ctx, func() { _ = rc.Close() })
	}
	if err := send(ue, d.Data); err != nil {
		stopClose()
		_ = ue.RemoteConn.Close()
		<-udpRelaySem
		return err
	}
	s.udpFlows.Store(key, ue)

	go func(ue *socks5.UDPExchange, dst string) {
		defer func() {
			stopClose()
			_ = ue.RemoteConn.Close()
			flowLock.Lock()
			s.udpFlows.Delete(key)
			flowLock.Unlock()
			<-udpRelaySem
		}()
		// A stack [65507]byte here escapes to the heap per goroutine (~64 KiB each);
		// with hundreds of DHT peers that dominates inuse_space.
		rbp := udpReadBufPool.Get().(*[]byte)
		b := *rbp
		defer udpReadBufPool.Put(rbp)
		for {
			select {
			case <-ch:
				return
			default:
				// Use full time.Duration (NewClassicServer only gets whole seconds).
				// int(cfg.UDPTimeout/time.Second) truncates e.g. 500ms to 0 → no deadline → stuck relays.
				if t := s.cfg.UDPTimeout; t > 0 {
					if err := ue.RemoteConn.SetReadDeadline(time.Now().Add(t)); err != nil {
						s.cfg.Logger.Printf("set read deadline on %s: %v", dst, err)
						return
					}
				}
				n, err := ue.RemoteConn.Read(b)
				if err != nil {
					return
				}
				a, haddr, hport, err := socks5.ParseAddress(dst)
				if err != nil {
					s.cfg.Logger.Printf("parse address %s: %v", dst, err)
					return
				}
				if a == socks5.ATYPDomain {
					haddr = haddr[1:]
				}
				dg := socks5.NewDatagram(a, haddr, hport, b[:n])
				wp := udpWireBufPool.Get().(*[]byte)
				w := (*wp)[:0]
				w = append(w, dg.Rsv...)
				w = append(w, dg.Frag)
				w = append(w, dg.Atyp)
				w = append(w, dg.DstAddr...)
				w = append(w, dg.DstPort...)
				w = append(w, dg.Data...)
				_, err = srv.UDPConn.WriteToUDP(w, ue.ClientAddr)
				*wp = w
				udpWireBufPool.Put(wp)
				if err != nil {
					return
				}
			}
		}
	}(ue, dst)

	return nil
}

type udpFlowKey struct {
	source, destination string
	association         *udpAssociation
}

func (s *SOCKS5Server) udpFlowLock(source, destination string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(source + "|" + destination))
	return &s.udpFlowLocks[h.Sum32()%uint32(len(s.udpFlowLocks))]
}
