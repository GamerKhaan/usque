package supervisor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type HealthResult struct {
	WARP    string        `json:"warp"`
	Latency time.Duration `json:"latency_ns"`
}

// Probe makes a fresh SOCKS connection for every HTTPS check. Hostname resolution
// is delegated to SOCKS, avoiding a successful host-side DNS lookup masking a
// broken tunnel DNS path in full socks mode. L4 mode itself uses host-side DNS.
type Probe struct {
	Address string
	URL     string
	Timeout time.Duration
	// TLSConfig is only needed by callers using a private, trusted trace endpoint.
	// The service CLI never disables TLS certificate verification.
	TLSConfig *tls.Config
}

func (p Probe) Check(ctx context.Context) (HealthResult, error) {
	started := time.Now()
	var result HealthResult
	if err := validateHealthURL(p.URL); err != nil {
		return result, err
	}
	if p.Timeout <= 0 {
		return result, fmt.Errorf("health timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	dialer, err := proxy.SOCKS5("tcp", p.Address, nil, &net.Dialer{Timeout: p.Timeout})
	if err != nil {
		return result, fmt.Errorf("create SOCKS dialer: %w", err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return result, fmt.Errorf("SOCKS dialer does not support cancellation")
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: contextDialer.DialContext, TLSClientConfig: p.TLSConfig,
		TLSHandshakeTimeout: p.Timeout, ResponseHeaderTimeout: p.Timeout, DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: p.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return result, fmt.Errorf("create health request: %w", err)
	}
	req.Header.Set("User-Agent", "usque-supervisor-health/1")
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("SOCKS HTTPS probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("trace returned HTTP %d", resp.StatusCode)
	}
	const maxTrace = 16 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTrace+1))
	if err != nil {
		return result, fmt.Errorf("read HTTPS trace: %w", err)
	}
	if len(body) > maxTrace {
		return result, fmt.Errorf("HTTPS trace exceeded maximum size")
	}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && key == "warp" {
			if value != "on" && value != "plus" {
				return result, fmt.Errorf("HTTPS trace did not confirm WARP")
			}
			result.WARP = value
		}
	}
	if result.WARP == "" {
		return result, fmt.Errorf("HTTPS trace is missing WARP confirmation")
	}
	result.Latency = time.Since(started)
	return result, nil
}
