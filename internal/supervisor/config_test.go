package supervisor

import (
	"slices"
	"testing"
)

func TestServiceDefaultsAndChildArguments(t *testing.T) {
	c, err := FromEnvironment(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if c.SOCKSAddress() != "127.0.0.1:903" || c.Mode != "socks" || c.MTU != 1280 || c.HealthFailures != 3 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if !slices.Contains(c.ChildArgs(), "--always-reconnect=true") || !slices.Contains(c.ChildArgs(), "--dial-timeout") {
		t.Fatalf("missing production flags: %v", c.ChildArgs())
	}
	c.Mode = "l4-socks"
	if slices.Contains(c.ChildArgs(), "--mtu") || slices.Contains(c.ChildArgs(), "--always-reconnect=true") {
		t.Fatalf("unsupported l4 flags: %v", c.ChildArgs())
	}
}

func TestEnvironmentRejectsUnsafeAndInvalidSettings(t *testing.T) {
	for key, value := range map[string]string{
		"USQUE_BIND": "0.0.0.0", "USQUE_PORT": "0", "USQUE_MTU": "1", "USQUE_MODE": "http-proxy",
		"USQUE_HEALTH_TIMEOUT": "0s", "USQUE_HEALTH_INTERVAL": "oops", "USQUE_HEALTH_FAILURES": "0",
		"USQUE_HTTP2": "yes please", "USQUE_BINARY": "relative", "USQUE_BACKOFF_MAX": "1ns",
		"USQUE_HEALTH_URL": "http://trace.example", "USQUE_ALLOW_PUBLIC": "not-a-bool",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := FromEnvironment(func(k string) string {
				if k == key {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
	_, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_MODE": "l4-socks", "USQUE_HTTP2": "true"}[k] })
	if err == nil {
		t.Fatal("unsupported l4 HTTP2 accepted")
	}
	c, err := FromEnvironment(func(k string) string { return map[string]string{"USQUE_BIND": "::", "USQUE_ALLOW_PUBLIC": "true"}[k] })
	if err != nil || c.SOCKSAddress() != "[::1]:903" {
		t.Fatalf("explicit public IPv6 opt-in: %+v %v", c, err)
	}
}
