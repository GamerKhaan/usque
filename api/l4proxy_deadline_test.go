package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func localL4Proxy(t *testing.T, handler http.HandlerFunc) *L4Proxy {
	t.Helper()
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certificateServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certificateServer.Certificate())
	certificateServer.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = server.Serve(udp) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = udp.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
			t.Error("HTTP/3 test server did not stop")
		}
	})
	proxy, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "example.com", NextProtos: []string{"h3"}},
		Endpoint:  udp.LocalAddr().(*net.UDPAddr), ConnectRetryCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Establish QUIC separately, so tests exercise a CONNECT response stall.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := proxy.getOrCreateClientConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.closeClientConnIfCurrent(client) })
	return proxy
}

func TestL4CONNECTResponseDeadline(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	proxy := localL4Proxy(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := proxy.DialContext(ctx, "192.0.2.1:443")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("CONNECT deadline error=%v elapsed=%v", err, time.Since(start))
	}
	select {
	case <-entered:
	default:
		t.Fatal("test did not reach stalled CONNECT response")
	}
}

func TestL4CONNECTSurvivesDialContextExpiry(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	proxy := localL4Proxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = w.Write([]byte("ok"))
		case <-r.Context().Done():
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	conn, err := proxy.DialContext(ctx, "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	<-ctx.Done()
	releaseOnce.Do(func() { close(release) })
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("established stream did not survive dial timeout: payload=%q error=%v", buf, err)
	}
}

type cancelJoinStream struct {
	responseReady chan struct{}
	cancelStarted chan struct{}
	cancelRelease chan struct{}
	cancelOnce    sync.Once
}

func (s *cancelJoinStream) SendRequestHeader(*http.Request) error { return nil }
func (s *cancelJoinStream) ReadResponse() (*http.Response, error) {
	<-s.responseReady
	return &http.Response{StatusCode: http.StatusOK}, nil
}
func (s *cancelJoinStream) SetDeadline(time.Time) error      { return nil }
func (s *cancelJoinStream) CancelWrite(quic.StreamErrorCode) {}
func (s *cancelJoinStream) CancelRead(quic.StreamErrorCode) {
	s.cancelOnce.Do(func() { close(s.cancelStarted); <-s.cancelRelease })
}

func TestL4CONNECTJoinsInFlightCancellation(t *testing.T) {
	s := &cancelJoinStream{responseReady: make(chan struct{}), cancelStarted: make(chan struct{}), cancelRelease: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- establishL4Connect(ctx, s, "192.0.2.1:443") }()
	cancel()
	select {
	case <-s.cancelStarted:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach stream")
	}
	close(s.responseReady)
	select {
	case <-done:
		t.Fatal("CONNECT returned while cancellation still used stream")
	case <-time.After(20 * time.Millisecond):
	}
	close(s.cancelRelease)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT cancellation did not finish")
	}
}
