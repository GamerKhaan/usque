package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
)

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type Config struct {
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointH2V4   string `json:"endpoint_h2_v4"`   // IPv4 address used in HTTP/2 mode
	EndpointH2V6   string `json:"endpoint_h2_v6"`   // IPv6 address used in HTTP/2 mode
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
//
// ReadConfig reads one bounded JSON document without changing global state.
// Unknown fields are tolerated for forward compatibility.
func ReadConfig(configPath string) (Config, error) {
	var cfg Config
	file, err := os.Open(configPath)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = file.Close() }()
	const maxSize = 1024 * 1024
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSize {
		return cfg, fmt.Errorf("config must be a regular file of at most 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxSize+1))
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config must contain a JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Config{}, fmt.Errorf("config contains trailing data")
	}
	return cfg, nil
}

func LoadConfig(configPath string) error {
	ConfigLoaded = false
	AppConfig = Config{}
	cfg, err := ReadConfig(configPath)
	if err != nil {
		return err
	}
	AppConfig = cfg
	ConfigLoaded = true
	return nil
}

// SaveConfig atomically writes private configuration with owner-only permissions.
func (c *Config) SaveConfig(configPath string) error {
	file, err := os.CreateTemp(filepath.Dir(configPath), ".usque-config-*")
	if err != nil {
		return fmt.Errorf("create config staging file: %w", err)
	}
	defer func() { _ = os.Remove(file.Name()) }()
	defer func() { _ = file.Close() }()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(file.Name(), configPath); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// Validate checks service-required configuration without including field values
// or credentials in errors. It does not prove that remote credentials are valid.
func (c *Config) Validate() error {
	if _, err := c.GetEcPrivateKey(); err != nil {
		return fmt.Errorf("invalid private_key")
	}
	if _, err := c.GetEcEndpointPublicKey(); err != nil {
		return fmt.Errorf("invalid endpoint_pub_key")
	}
	if c.ID == "" || c.AccessToken == "" {
		return fmt.Errorf("missing device ID or access token")
	}
	for _, f := range []struct {
		name, value    string
		ipv4, optional bool
	}{
		{"ipv4", c.IPv4, true, false}, {"ipv6", c.IPv6, false, false},
		{"endpoint_v4", c.EndpointV4, true, false}, {"endpoint_v6", c.EndpointV6, false, true},
		{"endpoint_h2_v4", c.EndpointH2V4, true, true}, {"endpoint_h2_v6", c.EndpointH2V6, false, true},
	} {
		if f.optional && f.value == "" {
			continue
		}
		a, err := netip.ParseAddr(f.value)
		if err != nil || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" || a.Is4() != f.ipv4 || a.Is4In6() {
			return fmt.Errorf("invalid %s address", f.name)
		}
	}
	return nil
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (c *Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (c *Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(c.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}
