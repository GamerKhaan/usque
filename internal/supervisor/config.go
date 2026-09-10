// Package supervisor manages the production proxy child and its data-plane health.
package supervisor

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config contains service settings, never WARP credentials.
type Config struct {
	Binary, ConfigPath, StatePath, Bind, Mode, HealthURL string
	Port, HealthFailures, MTU                            int
	HTTP2, AlwaysReconnect, AllowPublic                  bool
	HealthInterval, HealthTimeout, ShutdownTimeout       time.Duration
	DialTimeout, BackoffMin, BackoffMax, HealthyReset    time.Duration
}

// FromEnvironment validates the complete service profile before starting a child.
func FromEnvironment(getenv func(string) string) (Config, error) {
	c := Config{
		Binary: "/opt/usque/current/usque", ConfigPath: "/etc/usque/config.json", StatePath: "/run/usque/status.json",
		Bind: "127.0.0.1", Port: 903, Mode: "socks", MTU: 1280, AlwaysReconnect: true,
		HealthURL: "https://www.cloudflare.com/cdn-cgi/trace", HealthFailures: 3,
		HealthInterval: 20 * time.Second, HealthTimeout: 8 * time.Second, ShutdownTimeout: 8 * time.Second,
		DialTimeout: 8 * time.Second, BackoffMin: time.Second, BackoffMax: 30 * time.Second, HealthyReset: 2 * time.Minute,
	}
	for key, dst := range map[string]*string{
		"USQUE_BINARY": &c.Binary, "USQUE_CONFIG": &c.ConfigPath, "USQUE_STATE": &c.StatePath,
		"USQUE_BIND": &c.Bind, "USQUE_MODE": &c.Mode, "USQUE_HEALTH_URL": &c.HealthURL,
	} {
		if value := getenv(key); value != "" {
			*dst = value
		}
	}
	for key, dst := range map[string]*time.Duration{
		"USQUE_HEALTH_INTERVAL": &c.HealthInterval, "USQUE_HEALTH_TIMEOUT": &c.HealthTimeout,
		"USQUE_SHUTDOWN_TIMEOUT": &c.ShutdownTimeout, "USQUE_DIAL_TIMEOUT": &c.DialTimeout,
		"USQUE_BACKOFF_MIN": &c.BackoffMin, "USQUE_BACKOFF_MAX": &c.BackoffMax, "USQUE_HEALTHY_RESET": &c.HealthyReset,
	} {
		if value := getenv(key); value != "" {
			parsed, err := time.ParseDuration(value)
			if err != nil || parsed <= 0 {
				return c, fmt.Errorf("%s must be a positive duration (for example 8s)", key)
			}
			*dst = parsed
		}
	}
	for key, dst := range map[string]*int{"USQUE_PORT": &c.Port, "USQUE_MTU": &c.MTU, "USQUE_HEALTH_FAILURES": &c.HealthFailures} {
		if value := getenv(key); value != "" {
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return c, fmt.Errorf("%s must be an integer", key)
			}
			*dst = parsed
		}
	}
	for key, dst := range map[string]*bool{"USQUE_HTTP2": &c.HTTP2, "USQUE_ALWAYS_RECONNECT": &c.AlwaysReconnect, "USQUE_ALLOW_PUBLIC": &c.AllowPublic} {
		if value := getenv(key); value != "" {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return c, fmt.Errorf("%s must be true or false", key)
			}
			*dst = parsed
		}
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	absolute := func(path string) bool { return filepath.IsAbs(path) || strings.HasPrefix(path, "/") }
	if !absolute(c.Binary) || !absolute(c.ConfigPath) || !absolute(c.StatePath) {
		return fmt.Errorf("USQUE_BINARY, USQUE_CONFIG and USQUE_STATE must be absolute paths")
	}
	ip := net.ParseIP(c.Bind)
	if ip == nil {
		return fmt.Errorf("USQUE_BIND must be a literal IP address")
	}
	if !ip.IsLoopback() && !c.AllowPublic {
		return fmt.Errorf("non-loopback binding requires USQUE_ALLOW_PUBLIC=true; SOCKS is unauthenticated and unencrypted")
	}
	if c.Port < 1 || c.Port > 65535 || c.HealthFailures < 1 || c.HealthFailures > 1000 {
		return fmt.Errorf("USQUE_PORT must be 1..65535 and USQUE_HEALTH_FAILURES must be 1..1000")
	}
	if c.Mode != "socks" && c.Mode != "l4-socks" {
		return fmt.Errorf("USQUE_MODE must be socks or l4-socks")
	}
	if c.Mode == "l4-socks" && c.HTTP2 {
		return fmt.Errorf("l4-socks supports HTTP/3 only; select socks for USQUE_HTTP2=true")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("USQUE_MTU must be 576..65535; nondefault values need workload validation")
	}
	for _, d := range []time.Duration{c.HealthInterval, c.HealthTimeout, c.ShutdownTimeout, c.DialTimeout, c.BackoffMin, c.BackoffMax, c.HealthyReset} {
		if d <= 0 {
			return fmt.Errorf("all service durations must be positive")
		}
	}
	if c.BackoffMax < c.BackoffMin {
		return fmt.Errorf("USQUE_BACKOFF_MAX must be at least USQUE_BACKOFF_MIN")
	}
	return validateHealthURL(c.HealthURL)
}

func validateHealthURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || net.ParseIP(u.Hostname()) != nil {
		return fmt.Errorf("USQUE_HEALTH_URL must be an HTTPS hostname URL without credentials, query or fragment")
	}
	return nil
}

func (c Config) SOCKSAddress() string {
	bind := c.Bind
	if ip := net.ParseIP(bind); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			bind = "127.0.0.1"
		} else {
			bind = "::1"
		}
	}
	return net.JoinHostPort(bind, strconv.Itoa(c.Port))
}

func (c Config) ChildArgs() []string {
	args := []string{"-c", c.ConfigPath, c.Mode, "-b", c.Bind, "-p", strconv.Itoa(c.Port), "--dial-timeout", c.DialTimeout.String()}
	if c.Mode == "socks" {
		args = append(args, "--mtu", strconv.Itoa(c.MTU), "--always-reconnect="+strconv.FormatBool(c.AlwaysReconnect), "--http2="+strconv.FormatBool(c.HTTP2))
	}
	return args
}
