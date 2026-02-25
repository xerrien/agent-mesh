package agent

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func TestMCPACLBlocksUnknownCaller(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	allowed := nostr.Generate().Public().Hex()
	denied := nostr.Generate().Public().Hex()
	if err := node.AllowMCPToolCaller("local.echo", allowed); err != nil {
		t.Fatalf("allow caller: %v", err)
	}

	if _, _, err := node.executeMCPToolForRequest(context.Background(), denied, "r1", "local.echo", map[string]interface{}{"x": 1}); err == nil {
		t.Fatalf("expected denied caller to fail")
	}

	if _, _, err := node.executeMCPToolForRequest(context.Background(), allowed, "r2", "local.echo", map[string]interface{}{"x": 1}); err != nil {
		t.Fatalf("expected allowed caller to pass, got %v", err)
	}
}

func TestMCPToolRateLimit(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	requester := nostr.Generate().Public().Hex()
	if err := node.SetMCPToolRateLimit("local.echo", 1, time.Hour); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}

	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "r1", "local.echo", map[string]interface{}{"x": 1}); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "r2", "local.echo", map[string]interface{}{"x": 2}); err == nil {
		t.Fatalf("expected second call to hit rate limit")
	} else if !strings.Contains(strings.ToLower(err.Error()), "rate limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPIdempotencyDedupesExecution(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	requester := nostr.Generate().Public().Hex()
	if err := node.SetMCPToolRateLimit("test.counter", 1, time.Hour); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}

	count := 0
	if err := node.mcp.RegisterTool("test.counter", "counter", func(_ context.Context, _ map[string]interface{}) (interface{}, error) {
		count++
		return map[string]interface{}{"count": count}, nil
	}); err != nil {
		t.Fatalf("register tool: %v", err)
	}

	res1, deduped1, err := node.executeMCPToolForRequest(context.Background(), requester, "same-id", "test.counter", map[string]interface{}{})
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if deduped1 {
		t.Fatalf("first call should not be deduped")
	}

	res2, deduped2, err := node.executeMCPToolForRequest(context.Background(), requester, "same-id", "test.counter", map[string]interface{}{})
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if !deduped2 {
		t.Fatalf("second call should be deduped")
	}

	m1, ok1 := res1.(map[string]interface{})
	m2, ok2 := res2.(map[string]interface{})
	if !ok1 || !ok2 {
		t.Fatalf("expected map results")
	}
	if m1["count"] != m2["count"] || m1["count"] != 1 {
		t.Fatalf("expected cached count=1, got %v and %v", m1["count"], m2["count"])
	}
	if count != 1 {
		t.Fatalf("expected tool execution count=1, got %d", count)
	}
}

func TestMCPPolicyPersistsAcrossRestart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	db := filepath.Join(dir, "test.db")
	peer := nostr.Generate().Public().Hex()

	node1, err := NewAgentNode(db, dir)
	if err != nil {
		t.Fatalf("new node1: %v", err)
	}
	if err := node1.SetMCPDefaultRateLimit(11, 45*time.Second); err != nil {
		t.Fatalf("set default rate: %v", err)
	}
	if err := node1.SetMCPToolRateLimit("workspace.search", 3, 30*time.Second); err != nil {
		t.Fatalf("set tool rate: %v", err)
	}
	if err := node1.AllowMCPToolCaller("workspace.search", peer); err != nil {
		t.Fatalf("allow acl: %v", err)
	}
	if err := node1.SetMCPACLDefaultDeny(true); err != nil {
		t.Fatalf("set acl default deny: %v", err)
	}
	_ = node1.Stop()

	node2, err := NewAgentNode(db, dir)
	if err != nil {
		t.Fatalf("new node2: %v", err)
	}
	defer func() { _ = node2.Stop() }()

	p := node2.MCPPolicy()
	if p.DefaultRate.Limit != 11 || p.DefaultRate.WindowSec != 45 {
		t.Fatalf("unexpected persisted default rate: %#v", p.DefaultRate)
	}
	if len(p.ToolRates) == 0 || p.ToolRates[0].Tool != "workspace.search" || p.ToolRates[0].Limit != 3 || p.ToolRates[0].WindowSec != 30 {
		t.Fatalf("unexpected persisted tool rate: %#v", p.ToolRates)
	}
	acl := p.ToolACL["workspace.search"]
	if len(acl) != 1 || acl[0] != strings.ToLower(peer) {
		t.Fatalf("unexpected persisted acl: %#v", p.ToolACL)
	}
	if !p.ACLDefaultDeny {
		t.Fatalf("expected persisted acl default deny")
	}
}

func TestMCPACLDefaultDenyMode(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	requester := nostr.Generate().Public().Hex()
	if err := node.SetMCPACLDefaultDeny(true); err != nil {
		t.Fatalf("set default deny: %v", err)
	}

	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "x1", "local.echo", map[string]interface{}{"x": 1}); err == nil {
		t.Fatalf("expected call to fail in default-deny mode without explicit ACL")
	}
	if err := node.AllowMCPToolCaller("local.echo", requester); err != nil {
		t.Fatalf("allow caller: %v", err)
	}
	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "x2", "local.echo", map[string]interface{}{"x": 1}); err != nil {
		t.Fatalf("expected allowed caller to pass, got %v", err)
	}
}

func TestMCPRateLimitWindowExpires(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	requester := nostr.Generate().Public().Hex()
	if err := node.SetMCPToolRateLimit("local.echo", 1, 50*time.Millisecond); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}

	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "w1", "local.echo", map[string]interface{}{"x": 1}); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "w2", "local.echo", map[string]interface{}{"x": 2}); err == nil {
		t.Fatalf("expected second call to be rate limited")
	}
	time.Sleep(80 * time.Millisecond)
	if _, _, err := node.executeMCPToolForRequest(context.Background(), requester, "w3", "local.echo", map[string]interface{}{"x": 3}); err != nil {
		t.Fatalf("expected call after window expiry to pass, got %v", err)
	}
}

func TestMCPConcurrentExecution(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	requester := nostr.Generate().Public().Hex()
	if err := node.SetMCPToolRateLimit("test.concurrent", 1000, time.Second); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}

	var calls int64
	if err := node.mcp.RegisterTool("test.concurrent", "concurrency test tool", func(_ context.Context, args map[string]interface{}) (interface{}, error) {
		atomic.AddInt64(&calls, 1)
		return map[string]interface{}{"ok": true, "args": args}, nil
	}); err != nil {
		t.Fatalf("register tool: %v", err)
	}

	const workers = 20
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := node.executeMCPToolForRequest(context.Background(), requester, "c"+strconv.Itoa(i), "test.concurrent", map[string]interface{}{"i": float64(i)})
			errCh <- err
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent execution error: %v", err)
		}
	}
	if got := atomic.LoadInt64(&calls); got != workers {
		t.Fatalf("expected %d tool calls, got %d", workers, got)
	}
}
