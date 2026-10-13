package config

import (
	"path/filepath"
	"testing"
)

func TestExampleConfigurationsValidateAndResolveKeyPaths(t *testing.T) {
	root := filepath.Join("..", "..", "config")
	relay, err := LoadRelay(filepath.Join(root, "relay.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(relay.Devices) != 1 || relay.Devices[0].ID != "example-device" {
		t.Fatalf("unexpected relay config: %#v", relay)
	}
	agent, err := LoadAgent(filepath.Join(root, "agent.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(agent.PrivateKeyFile) || !filepath.IsAbs(agent.LogFile) {
		t.Fatalf("relative paths were not resolved: %#v", agent)
	}
	if err = agent.Policy.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestRelayBearerTokenEnvironmentOverride(t *testing.T) {
	t.Setenv("ATO_MCP_BEARER_TOKEN", "test-only-token-value-0123456789abcdef")
	cfg, err := LoadRelay(filepath.Join("..", "..", "config", "relay.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCPBearerToken != "test-only-token-value-0123456789abcdef" {
		t.Fatal("environment override was not used")
	}
}
