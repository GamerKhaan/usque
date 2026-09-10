package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func validTestConfig(t *testing.T) Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Config{PrivateKey: base64.StdEncoding.EncodeToString(priv), EndpointPubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), ID: "test-device", AccessToken: "test-token", IPv4: "172.16.0.2", IPv6: "2606:4700:110:8::2", EndpointV4: "162.159.198.1"}
}

func TestConfigRoundTripUsesReceiver(t *testing.T) {
	cfg := validTestConfig(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SaveConfig(path); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg {
		t.Fatal("saved config does not match receiver")
	}
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	cfg.ID = "updated"
	if err := cfg.SaveConfig(path); err != nil {
		t.Fatal(err)
	}
	got, err = ReadConfig(path)
	if err != nil || got.ID != "updated" {
		t.Fatal("atomic replacement failed", err)
	}
}

func TestConfigRejectsMalformedAndTrailingData(t *testing.T) {
	for _, content := range []string{"secret-not-json", `{} {}`, `{"private_key":[]}`, strings.Repeat("x", 1024*1024+1)} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadConfig(path)
		if err == nil {
			t.Fatal("accepted malformed configuration")
		}
		if strings.Contains(err.Error(), "secret-not-json") {
			t.Fatal("error leaked source data")
		}
	}
}

func TestValidationRedactsSecrets(t *testing.T) {
	for _, field := range []string{"key", "pubkey", "token", "ipv4", "ipv6", "endpoint"} {
		cfg := validTestConfig(t)
		switch field {
		case "key":
			cfg.PrivateKey = "secret-marker"
		case "pubkey":
			cfg.EndpointPubKey = "secret-marker"
		case "token":
			cfg.AccessToken = ""
		case "ipv4":
			cfg.IPv4 = "secret-marker"
		case "ipv6":
			cfg.IPv6 = "::ffff:192.0.2.1"
		case "endpoint":
			cfg.EndpointV4 = "0.0.0.0"
		}
		err := cfg.Validate()
		if err == nil || strings.Contains(err.Error(), "secret-marker") {
			t.Fatalf("unsafe validation for %s", field)
		}
	}
}

func TestFailedLoadClearsPreviousConfig(t *testing.T) {
	old, loaded := AppConfig, ConfigLoaded
	defer func() { AppConfig, ConfigLoaded = old, loaded }()
	AppConfig, ConfigLoaded = validTestConfig(t), true
	if err := LoadConfig(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing config accepted")
	}
	if ConfigLoaded || AppConfig != (Config{}) {
		t.Fatal("stale credentials retained")
	}
}
