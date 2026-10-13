// Package config loads and validates relay and agent configuration files.
package config

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
)

type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked,omitempty"`
}
type Relay struct {
	ListenAddress  string   `json:"listen_address"`
	PublicURL      string   `json:"public_url"`
	MCPBearerToken string   `json:"mcp_bearer_token"`
	Devices        []Device `json:"devices"`
	LogLevel       string   `json:"log_level,omitempty"`
}
type Agent struct {
	RelayURL       string        `json:"relay_url"`
	DeviceID       string        `json:"device_id"`
	DeviceName     string        `json:"device_name"`
	PrivateKeyFile string        `json:"private_key_file"`
	LogFile        string        `json:"log_file,omitempty"`
	Policy         policy.Policy `json:"policy"`
	ReconnectMax   time.Duration `json:"-"`
}

func LoadRelay(path string) (Relay, error) {
	var c Relay
	e := load(path, &c)
	if e != nil {
		return c, e
	}
	if v := os.Getenv("ATO_RELAY_LISTEN"); v != "" {
		c.ListenAddress = v
	}
	if v := os.Getenv("ATO_PUBLIC_URL"); v != "" {
		c.PublicURL = v
	}
	if v := os.Getenv("ATO_MCP_BEARER_TOKEN"); v != "" {
		c.MCPBearerToken = v
	}
	if c.ListenAddress == "" {
		c.ListenAddress = "127.0.0.1:8443"
	}
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return c, errors.New("public_url must be an HTTPS URL")
		}
	}
	if c.MCPBearerToken != "" {
		if e = auth.ValidateMCPToken(c.MCPBearerToken); e != nil {
			return c, e
		}
	}
	if len(c.Devices) == 0 {
		return c, errors.New("relay requires at least one registered device")
	}
	if len(c.Devices) > 64 {
		return c, errors.New("relay supports at most 64 registered devices in this MVP")
	}
	seen := map[string]bool{}
	for _, d := range c.Devices {
		if d.ID == "" || d.Name == "" {
			return c, errors.New("each device requires id and name")
		}
		if seen[d.ID] {
			return c, fmt.Errorf("duplicate device %q", d.ID)
		}
		seen[d.ID] = true
		if !d.Revoked {
			if _, e = auth.DecodeKey(d.PublicKey, ed25519.PublicKeySize); e != nil {
				return c, fmt.Errorf("device %q: %w", d.ID, e)
			}
		}
	}
	return c, nil
}
func LoadAgent(path string) (Agent, error) {
	var c Agent
	e := load(path, &c)
	if e != nil {
		return c, e
	}
	if v := os.Getenv("ATO_AGENT_RELAY_URL"); v != "" {
		c.RelayURL = v
	}
	if v := os.Getenv("ATO_AGENT_DEVICE_ID"); v != "" {
		c.DeviceID = v
	}
	if v := os.Getenv("ATO_AGENT_PRIVATE_KEY_FILE"); v != "" {
		c.PrivateKeyFile = v
	}
	if v := os.Getenv("ATO_AGENT_LOG_FILE"); v != "" {
		c.LogFile = v
	}
	base, e := filepath.Abs(filepath.Dir(path))
	if e != nil {
		return c, e
	}
	if !filepath.IsAbs(c.PrivateKeyFile) {
		c.PrivateKeyFile = filepath.Join(base, c.PrivateKeyFile)
	}
	if c.LogFile != "" && !filepath.IsAbs(c.LogFile) {
		c.LogFile = filepath.Join(base, c.LogFile)
	}
	if c.RelayURL == "" || c.DeviceID == "" || c.PrivateKeyFile == "" {
		return c, errors.New("agent requires relay_url, device_id, and private_key_file")
	}
	u, err := url.Parse(c.RelayURL)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return c, errors.New("relay_url must be a ws:// or wss:// URL")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	local := strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
	if !local && u.Scheme != "wss" {
		return c, errors.New("non-loopback agent connections require wss://")
	}
	if c.ReconnectMax == 0 {
		c.ReconnectMax = 60 * time.Second
	}
	if e = c.Policy.Validate(); e != nil {
		return c, e
	}
	return c, nil
}
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	key, e := auth.DecodeKey(string(bytesTrimSpace(b)), ed25519.PrivateKeySize)
	if e != nil {
		return nil, e
	}
	return ed25519.PrivateKey(key), nil
}
func load(path string, dst any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if e = d.Decode(dst); e != nil {
		return e
	}
	return nil
}
func SaveJSON(path string, value any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	tmp, e := os.CreateTemp(filepath.Dir(path), ".config-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(b); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Chmod(0600); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Sync(); e != nil {
		tmp.Close()
		return e
	}
	if e = tmp.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}
func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
