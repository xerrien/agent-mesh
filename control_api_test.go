package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"agentswarm/pkg/agent"
	"fiatjaf.com/nostr"
)

func TestControlAPIMCPPolicyHandlers(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := agent.NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	c := &controlAPIServer{node: node}
	peer := nostr.Generate().Public().Hex()

	allowReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/acl/allow", strings.NewReader(`{"tool":"workspace.search","pubkey":"`+peer+`"}`))
	allowRec := httptest.NewRecorder()
	c.handleMCPACLAllow(allowRec, allowReq)
	if allowRec.Code != http.StatusOK {
		t.Fatalf("allow status=%d body=%s", allowRec.Code, allowRec.Body.String())
	}

	rateReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/rate", strings.NewReader(`{"tool":"workspace.search","limit":7,"window_sec":60}`))
	rateRec := httptest.NewRecorder()
	c.handleMCPRate(rateRec, rateReq)
	if rateRec.Code != http.StatusOK {
		t.Fatalf("rate status=%d body=%s", rateRec.Code, rateRec.Body.String())
	}

	defaultReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/acl/default", strings.NewReader(`{"default_deny":true}`))
	defaultRec := httptest.NewRecorder()
	c.handleMCPACLDefault(defaultRec, defaultReq)
	if defaultRec.Code != http.StatusOK {
		t.Fatalf("default acl status=%d body=%s", defaultRec.Code, defaultRec.Body.String())
	}

	policyReq := httptest.NewRequest(http.MethodGet, "/v1/mcp/policy", nil)
	policyRec := httptest.NewRecorder()
	c.handleMCPPolicy(policyRec, policyReq)
	if policyRec.Code != http.StatusOK {
		t.Fatalf("policy status=%d body=%s", policyRec.Code, policyRec.Body.String())
	}

	var body struct {
		ToolRates      []agent.MCPRatePolicy `json:"tool_rates"`
		ToolACL        map[string][]string   `json:"tool_acl"`
		ACLDefaultDeny bool                  `json:"acl_default_deny"`
	}
	if err := json.Unmarshal(policyRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode policy body: %v", err)
	}
	if len(body.ToolRates) == 0 || body.ToolRates[0].Tool != "workspace.search" {
		t.Fatalf("expected workspace.search rate in policy, got %#v", body.ToolRates)
	}
	acl := body.ToolACL["workspace.search"]
	if len(acl) != 1 || acl[0] != strings.ToLower(peer) {
		t.Fatalf("expected ACL peer in policy, got %#v", body.ToolACL)
	}
	if !body.ACLDefaultDeny {
		t.Fatalf("expected acl_default_deny=true")
	}
}

func TestControlAPIMCPErrorPaths(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := agent.NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	c := &controlAPIServer{node: node}

	// Wrong method
	denyMethodReq := httptest.NewRequest(http.MethodGet, "/v1/mcp/acl/allow", nil)
	denyMethodRec := httptest.NewRecorder()
	c.handleMCPACLAllow(denyMethodRec, denyMethodReq)
	if denyMethodRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", denyMethodRec.Code)
	}

	// Invalid JSON/body
	badJSONReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/rate", strings.NewReader(`{"tool":"workspace.search","limit":"x"}`))
	badJSONRec := httptest.NewRecorder()
	c.handleMCPRate(badJSONRec, badJSONReq)
	if badJSONRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json/body, got %d body=%s", badJSONRec.Code, badJSONRec.Body.String())
	}

	// Missing fields / invalid values
	missingReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/acl/allow", strings.NewReader(`{"tool":"","pubkey":""}`))
	missingRec := httptest.NewRecorder()
	c.handleMCPACLAllow(missingRec, missingReq)
	if missingRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing tool/pubkey, got %d body=%s", missingRec.Code, missingRec.Body.String())
	}
}

func TestControlAPIAuthTokenAndRateLimit(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := agent.NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	c := &controlAPIServer{
		node:  node,
		token: "secret-token",
		rate:  make(map[string]rateWindow),
	}

	protected := c.withAuth(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
	})

	unauthReq := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	unauthReq.RemoteAddr = "127.0.0.1:5000"
	unauthRec := httptest.NewRecorder()
	protected(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got %d", unauthRec.Code)
	}

	authReq := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	authReq.RemoteAddr = "127.0.0.1:5000"
	authReq.Header.Set("X-AgentSwarm-Token", "secret-token")
	authRec := httptest.NewRecorder()
	protected(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid token, got %d", authRec.Code)
	}

	for i := 0; i < controlRateLimitCount; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
		req.RemoteAddr = "10.0.0.2:6000"
		req.Header.Set("X-AgentSwarm-Token", "secret-token")
		rec := httptest.NewRecorder()
		protected(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 before limit, got %d on iteration %d", rec.Code, i)
		}
	}

	overReq := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	overReq.RemoteAddr = "10.0.0.2:6000"
	overReq.Header.Set("X-AgentSwarm-Token", "secret-token")
	overRec := httptest.NewRecorder()
	protected(overRec, overReq)
	if overRec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after rate limit, got %d", overRec.Code)
	}
}





