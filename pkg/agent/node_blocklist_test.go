package agent

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

func TestBlocklistLifecycle(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	peerA := nostr.Generate().Public().Hex()
	peerB := nostr.Generate().Public().Hex()

	if err := node.BlockPeer(peerB); err != nil {
		t.Fatalf("block peerB: %v", err)
	}
	if err := node.BlockPeer(peerA); err != nil {
		t.Fatalf("block peerA: %v", err)
	}

	blocked := node.BlockedPeers()
	if len(blocked) != 2 {
		t.Fatalf("expected 2 blocked peers, got %d", len(blocked))
	}
	expected := []string{peerA, peerB}
	sort.Strings(expected)
	if blocked[0] != expected[0] || blocked[1] != expected[1] {
		t.Fatalf("blocked peers mismatch: got %#v expected %#v", blocked, expected)
	}

	if !node.UnblockPeer(peerA) {
		t.Fatalf("expected unblock peerA to return true")
	}
	if node.UnblockPeer(peerA) {
		t.Fatalf("expected second unblock peerA to return false")
	}
}

func TestSendTypedFailsForBlockedPeer(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	peer := nostr.Generate().Public().Hex()
	if err := node.BlockPeer(peer); err != nil {
		t.Fatalf("block peer: %v", err)
	}

	_, err = node.SendTyped(context.Background(), peer, MessageTypePing, map[string]interface{}{"probe": "x"})
	if err == nil {
		t.Fatalf("expected blocked peer send to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "blocked") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBlocklistPersistsAcrossRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	db := filepath.Join(dir, "test.db")
	peer := nostr.Generate().Public().Hex()

	node1, err := NewAgentNode(db, dir)
	if err != nil {
		t.Fatalf("new node1: %v", err)
	}
	if err := node1.BlockPeer(peer); err != nil {
		t.Fatalf("block peer: %v", err)
	}
	_ = node1.Stop()

	node2, err := NewAgentNode(db, dir)
	if err != nil {
		t.Fatalf("new node2: %v", err)
	}
	defer func() { _ = node2.Stop() }()

	if !node2.IsBlockedPeer(peer) {
		t.Fatalf("expected peer to remain blocked after restart")
	}
}

func TestBlockPeerCleansPeerState(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	peer := nostr.Generate().Public().Hex()
	node.mu.Lock()
	node.knownPeers[peer] = struct{}{}
	node.peerCapabilities[peer] = AgentCapability{Name: "local.echo", Description: "test"}
	node.peerRelays[peer] = []string{"wss://relay.example"}
	node.mu.Unlock()

	if err := node.BlockPeer(peer); err != nil {
		t.Fatalf("block peer: %v", err)
	}
	node.mu.RLock()
	_, inKnown := node.knownPeers[peer]
	_, inCaps := node.peerCapabilities[peer]
	_, inRelays := node.peerRelays[peer]
	node.mu.RUnlock()
	if inKnown || inCaps || inRelays {
		t.Fatalf("expected peer runtime state to be removed on block")
	}
}
