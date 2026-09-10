package internal

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type relayErrorConn struct {
	net.Conn
	readErr, writeErr error
}

func (c *relayErrorConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}

func (c *relayErrorConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(p)
}

// A peer can acknowledge FIN without sending its own FIN or further data.
func (c *relayErrorConn) CloseWrite() error { return nil }

func TestTCPRelayFatalErrorClosesBothDirections(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			a, client := net.Pipe()
			b, remote := net.Pipe()
			fault := errors.New("connection reset")
			left, right := &relayErrorConn{Conn: a}, &relayErrorConn{Conn: b}
			if direction == "read" {
				left.readErr = fault
			} else {
				right.writeErr = fault
			}
			done := make(chan struct{})
			t.Cleanup(func() {
				_ = a.Close()
				_ = b.Close()
				_ = client.Close()
				_ = remote.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("relay goroutine survived connection cleanup")
				}
			})
			s := testSOCKSServer(t)
			go func() { s.relayTCP(left, right, 0); close(done) }()
			if direction == "write" {
				if err := client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				_, _ = client.Write([]byte("request"))
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("fatal error left the opposite relay blocked")
			}
			for _, peer := range []net.Conn{client, remote} {
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatal(err)
				}
				if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("peer read after fatal relay error = %v, want EOF", err)
				}
			}
		})
	}
}

func TestTCPRelayPreservesHalfClose(t *testing.T) {
	left, client := tcpPair(t)
	right, remote := tcpPair(t)
	for _, conn := range []net.Conn{client, remote} {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	s := testSOCKSServer(t)
	go func() { s.relayTCP(left, right, 0); close(done) }()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("half-close relay did not stop")
		}
	})
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(remote); err != nil || string(got) != "request" {
		t.Fatalf("request after client FIN = %q, error %v", got, err)
	}
	// Servers may send their response only after the complete request and FIN.
	if _, err := remote.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := remote.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(client); err != nil || string(got) != "response" {
		t.Fatalf("response after server FIN = %q, error %v", got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not return after both FINs")
	}
}
