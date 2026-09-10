package internal

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/txthinking/socks5"
)

func replyDeadlineRequest() *socks5.Request {
	return &socks5.Request{Cmd: socks5.CmdConnect, Atyp: socks5.ATYPIPv4,
		DstAddr: []byte{192, 0, 2, 1}, DstPort: []byte{1, 187}}
}

func TestSOCKSReplyAfterDialTimeout(t *testing.T) {
	s := testSOCKSServer(t)
	s.cfg.DialTimeout = 30 * time.Millisecond
	s.cfg.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.connectTCP(server, replyDeadlineRequest())
		_ = server.Close()
		done <- err
	}()
	reply, err := socks5.NewReplyFrom(client)
	if err != nil {
		t.Fatalf("dial timeout must return a SOCKS failure reply, got %v", err)
	}
	if reply.Rep != socks5.RepHostUnreachable {
		t.Fatalf("reply code = %d, want host unreachable", reply.Rep)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dial error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT handler did not finish")
	}
}

type replyDeadlineConn struct {
	net.Conn
	closed        atomic.Bool
	writeDeadline func(time.Time) error
}

func (c *replyDeadlineConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 12345}
}

func (c *replyDeadlineConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c *replyDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if c.writeDeadline != nil {
		return c.writeDeadline(deadline)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestSOCKSSuccessReplyGetsFreshDeadline(t *testing.T) {
	s := testSOCKSServer(t)
	s.cfg.DialTimeout = 30 * time.Millisecond
	remote, remotePeer := net.Pipe()
	defer func() { _ = remote.Close(); _ = remotePeer.Close() }()
	rc := &replyDeadlineConn{Conn: remote}
	s.cfg.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) {
		// A dial can succeed at the boundary while the original deadline expires.
		<-ctx.Done()
		return rc, nil
	}
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := s.connectTCP(server, replyDeadlineRequest())
		if conn != nil {
			_ = conn.Close()
		}
		_ = server.Close()
		done <- err
	}()
	reply, err := socks5.NewReplyFrom(client)
	if err != nil || reply.Rep != socks5.RepSuccess {
		t.Fatalf("successful dial reply = %v, error = %v", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatalf("CONNECT error = %v", err)
	}
}

func TestSOCKSReplyDeadlineFailureClosesRemote(t *testing.T) {
	s := testSOCKSServer(t)
	remote, remotePeer := net.Pipe()
	defer func() { _ = remote.Close(); _ = remotePeer.Close() }()
	rc := &replyDeadlineConn{Conn: remote}
	s.cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { return rc, nil }
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	deadlineFailure := errors.New("injected deadline failure")
	calls := 0
	cleared := false
	c := &replyDeadlineConn{Conn: server, writeDeadline: func(deadline time.Time) error {
		calls++
		if calls == 2 {
			return deadlineFailure
		}
		if deadline.IsZero() {
			cleared = true
		}
		return nil
	}}
	conn, err := s.connectTCP(c, replyDeadlineRequest())
	if conn != nil || !errors.Is(err, deadlineFailure) {
		t.Fatalf("connection=%v error=%v", conn, err)
	}
	if !rc.closed.Load() || !cleared {
		t.Fatalf("remote closed=%v, client deadline cleared=%v", rc.closed.Load(), cleared)
	}
}
