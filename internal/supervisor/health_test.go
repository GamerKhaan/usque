package supervisor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSOCKS is a controlled SOCKS endpoint, independent of the production SOCKS
// implementation. It deliberately forwards the requested hostname to a local
// TLS server so CI never needs DNS, the Internet or WARP credentials.
func testSOCKS(t *testing.T, target, mode string) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	names := make(chan string, 100)
	done := make(chan struct{})
	var mu sync.Mutex
	var connections []net.Conn
	var wg sync.WaitGroup
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				if mode == "hang" {
					_, _ = io.Copy(io.Discard, conn)
					return
				}
				header := make([]byte, 2)
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				if mode == "reject" {
					_, _ = conn.Write([]byte{5, 255})
					return
				}
				if _, err := conn.Write([]byte{5, 0}); err != nil {
					return
				}
				req := make([]byte, 5)
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				if req[3] != 3 {
					return
				} // Domain-name form is required by this test.
				destination := make([]byte, int(req[4])+2)
				if _, err := io.ReadFull(conn, destination); err != nil {
					return
				}
				name := string(destination[:len(destination)-2])
				port := binary.BigEndian.Uint16(destination[len(destination)-2:])
				names <- fmt.Sprintf("%s:%d", name, port)
				if mode == "dns-failure" {
					_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				upstream, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(copied) }()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return listener.Addr().String(), names
}

func localProbe(t *testing.T, handler http.HandlerFunc, mode string) (Probe, <-chan string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	address, names := testSOCKS(t, server.Listener.Addr().String(), mode)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return Probe{
		Address: address, URL: "https://example.com:" + port + "/cdn-cgi/trace", Timeout: 300 * time.Millisecond,
		TLSConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}, names
}

func TestHTTPSHealthThroughSOCKS(t *testing.T) {
	for _, warp := range []string{"on", "plus"} {
		t.Run(warp, func(t *testing.T) {
			probe, names := localProbe(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "warp="+warp) }, "")
			result, err := probe.Check(context.Background())
			if err != nil || result.WARP != warp || result.Latency <= 0 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if name := <-names; !strings.HasPrefix(name, "example.com:") {
				t.Fatalf("SOCKS did not receive hostname: %s", name)
			}
		})
	}
}

func TestHTTPSHealthRejectsBrokenPaths(t *testing.T) {
	for _, tc := range []struct {
		name, mode, body string
		status           int
	}{
		{"warp-off", "", "warp=off\n", 200}, {"missing-warp", "", "ip=127.0.0.1\n", 200},
		{"http-error", "", "warp=on\n", 503}, {"redirect", "", "warp=on\n", 302},
		{"too-large", "", strings.Repeat("x", 17000) + "\nwarp=on\n", 200},
		{"socks-negotiation", "reject", "", 200}, {"dns-failure", "dns-failure", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, _ := localProbe(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}, tc.mode)
			if _, err := probe.Check(context.Background()); err == nil {
				t.Fatal("broken path accepted")
			}
		})
	}
	t.Run("untrusted-tls", func(t *testing.T) {
		probe, _ := localProbe(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "warp=on") }, "")
		probe.TLSConfig = nil
		if _, err := probe.Check(context.Background()); err == nil {
			t.Fatal("untrusted TLS accepted")
		}
	})
	t.Run("listener-unavailable", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		probe := Probe{Address: address, URL: "https://example.com/trace", Timeout: time.Second}
		if _, err := probe.Check(context.Background()); err == nil {
			t.Fatal("missing listener accepted")
		}
	})
}

func TestHealthTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"hang", "headers", "body"} {
		t.Run(mode, func(t *testing.T) {
			probe, _ := localProbe(t, func(w http.ResponseWriter, req *http.Request) {
				if mode == "body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				<-req.Context().Done()
			}, mode)
			probe.Timeout = 60 * time.Millisecond
			started := time.Now()
			if _, err := probe.Check(context.Background()); err == nil {
				t.Fatal("hung path accepted")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("timeout not enforced: %s", elapsed)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			started = time.Now()
			if _, err := probe.Check(ctx); err == nil {
				t.Fatal("cancellation ignored")
			}
			if time.Since(started) > time.Second {
				t.Fatal("cancellation took too long")
			}
		})
	}
}

func TestHealthURLRequiresHTTPSAndHostname(t *testing.T) {
	for _, raw := range []string{"http://example.com/trace", "https://127.0.0.1/trace", "https://name:secret@example.com/", "https://example.com/?token=secret", "https://example.com/#fragment"} {
		if validateHealthURL(raw) == nil {
			t.Fatalf("accepted unsuitable URL %s", raw)
		}
	}
}
