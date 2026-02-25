package main

import (
	"os"
	"path/filepath"
	"testing"

	"agentmesh/pkg/agent"
)

func TestLoadStartupProfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "agentmesh.toml")
	content := `
headless = true
bootstrap = "wss://nos.lol"
auto_connect = ["abcd"]
blocked_peers = ["efgh"]
mcp_default_rate_limit = 20
mcp_default_rate_window_sec = 60
mcp_acl_default_deny = true

[[mcp_tool_rates]]
tool = "workspace.search"
limit = 5
window_sec = 60

[[mcp_tool_acl]]
tool = "workspace.search"
peers = ["beef"]

[[auto_advertise]]
name = "workspace.search"
description = "search"
loop = true
ttl_sec = 120
`
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	profile, err := loadStartupProfile(p)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if profile == nil || !profile.Headless {
		t.Fatalf("expected headless profile")
	}
	if profile.Bootstrap != "wss://nos.lol" {
		t.Fatalf("unexpected bootstrap: %s", profile.Bootstrap)
	}
	if len(profile.AutoConnect) != 1 {
		t.Fatalf("unexpected auto_connect length: %d", len(profile.AutoConnect))
	}
	if len(profile.BlockedPeers) != 1 || profile.BlockedPeers[0] != "efgh" {
		t.Fatalf("unexpected blocked_peers")
	}
	if profile.MCPDefaultRateLimit != 20 || profile.MCPDefaultRateWindowSec != 60 {
		t.Fatalf("unexpected mcp default rate")
	}
	if profile.MCPACLDefaultDeny == nil || !*profile.MCPACLDefaultDeny {
		t.Fatalf("expected mcp_acl_default_deny=true")
	}
	if len(profile.MCPToolRates) != 1 || profile.MCPToolRates[0].Tool != "workspace.search" {
		t.Fatalf("unexpected mcp_tool_rates")
	}
	if len(profile.MCPToolACL) != 1 || profile.MCPToolACL[0].Tool != "workspace.search" {
		t.Fatalf("unexpected mcp_tool_acl")
	}
	if len(profile.AutoAdvertise) != 1 || profile.AutoAdvertise[0].Name != "workspace.search" {
		t.Fatalf("unexpected auto_advertise")
	}
}

func TestApplyStartupProfileNilSafe(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := agent.NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()
	if err := applyStartupProfile(node, nil); err != nil {
		t.Fatalf("expected nil profile to be no-op, got %v", err)
	}
}
