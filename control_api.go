package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentmesh/pkg/agent"
)

type controlAPIServer struct {
	node  *agent.AgentNode
	token string
	srv   *http.Server
	mu    sync.Mutex
	rate  map[string]rateWindow
}

type rateWindow struct {
	start time.Time
	count int
}

const (
	controlRateLimitCount  = 120
	controlRateLimitWindow = time.Minute
	controlShutdownTimeout = 3 * time.Second
	controlConnectTimeout  = 20 * time.Second
	controlSendTimeout     = 30 * time.Second
)

func startControlAPI(listenAddr string, node *agent.AgentNode, token string) (*controlAPIServer, error) {
	if node == nil {
		return nil, fmt.Errorf("node cannot be nil")
	}
	c := &controlAPIServer{
		node:  node,
		token: strings.TrimSpace(token),
		rate:  make(map[string]rateWindow),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", c.withAuth(c.handleStatus))
	mux.HandleFunc("/v1/peers", c.withAuth(c.handlePeers))
	mux.HandleFunc("/v1/connect", c.withAuth(c.handleConnect))
	mux.HandleFunc("/v1/send", c.withAuth(c.handleSend))
	mux.HandleFunc("/v1/blocked", c.withAuth(c.handleBlocked))
	mux.HandleFunc("/v1/block", c.withAuth(c.handleBlock))
	mux.HandleFunc("/v1/unblock", c.withAuth(c.handleUnblock))
	mux.HandleFunc("/v1/mcp/policy", c.withAuth(c.handleMCPPolicy))
	mux.HandleFunc("/v1/mcp/acl/allow", c.withAuth(c.handleMCPACLAllow))
	mux.HandleFunc("/v1/mcp/acl/deny", c.withAuth(c.handleMCPACLDeny))
	mux.HandleFunc("/v1/mcp/acl/clear", c.withAuth(c.handleMCPACLClear))
	mux.HandleFunc("/v1/mcp/acl/default", c.withAuth(c.handleMCPACLDefault))
	mux.HandleFunc("/v1/mcp/rate", c.withAuth(c.handleMCPRate))
	mux.HandleFunc("/v1/mcp/rate/clear", c.withAuth(c.handleMCPRateClear))
	mux.HandleFunc("/v1/inbox", c.withAuth(c.handleInbox))
	mux.HandleFunc("/v1/inbox/unread", c.withAuth(c.handleInboxUnread))
	mux.HandleFunc("/v1/inbox/ack", c.withAuth(c.handleInboxAck))

	c.srv = &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := c.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[ControlAPI] Listen error: %v\n", err)
		}
	}()
	return c, nil
}

func (c *controlAPIServer) Stop() error {
	if c == nil || c.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), controlShutdownTimeout)
	defer cancel()
	return c.srv.Shutdown(ctx)
}

func (c *controlAPIServer) withAuth(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.allowRequest(r) {
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{"error": "rate limit exceeded"})
			return
		}
		if c.token != "" {
			in := []byte(strings.TrimSpace(r.Header.Get("X-AgentMesh-Token")))
			expected := []byte(c.token)
			if len(in) != len(expected) || subtle.ConstantTimeCompare(in, expected) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (c *controlAPIServer) allowRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || host == "" {
		host = strings.TrimSpace(r.RemoteAddr)
		if host == "" {
			host = "unknown"
		}
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.rate[host]
	if w.start.IsZero() || now.Sub(w.start) >= controlRateLimitWindow {
		w = rateWindow{start: now, count: 0}
	}
	if w.count >= controlRateLimitCount {
		c.rate[host] = w
		return false
	}
	w.count++
	c.rate[host] = w
	return true
}

func (c *controlAPIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	peers := c.node.ConnectedPeers()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"node_id":    c.node.NodeID(),
		"relays":     c.node.RelayURLs(),
		"peer_count": len(peers),
		"peers":      peers,
	})
}

func (c *controlAPIServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	peers := c.node.ConnectedPeers()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count": len(peers),
		"peers": peers,
	})
}

func (c *controlAPIServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		PubKey    string `json:"pubkey"`
		TimeoutMs int64  `json:"timeout_ms"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	pubKey := strings.TrimSpace(req.PubKey)
	if pubKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "pubkey is required"})
		return
	}
	timeout := controlConnectTimeout
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	if err := c.node.ConnectPeer(ctx, pubKey); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "pubkey": pubKey})
}

func (c *controlAPIServer) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		PubKey    string                 `json:"pubkey"`
		Type      string                 `json:"type"`
		Payload   map[string]interface{} `json:"payload"`
		TimeoutMs int64                  `json:"timeout_ms"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	pubKey := strings.TrimSpace(req.PubKey)
	msgType := strings.TrimSpace(strings.ToLower(req.Type))
	if pubKey == "" || msgType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "pubkey and type are required"})
		return
	}
	if req.Payload == nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "payload must be a JSON object"})
		return
	}
	timeout := controlSendTimeout
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	resp, err := c.node.SendTyped(ctx, pubKey, msgType, req.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"pubkey":   pubKey,
		"type":     msgType,
		"response": resp,
	})
}

func (c *controlAPIServer) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	peers := c.node.BlockedPeers()
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(peers), "peers": peers})
}

func (c *controlAPIServer) handleBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	pubKey := strings.TrimSpace(req.PubKey)
	if pubKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "pubkey is required"})
		return
	}
	if err := c.node.BlockPeer(pubKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "pubkey": pubKey})
}

func (c *controlAPIServer) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	pubKey := strings.TrimSpace(req.PubKey)
	if pubKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "pubkey is required"})
		return
	}
	ok := c.node.UnblockPeer(pubKey)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok, "pubkey": pubKey})
}

func (c *controlAPIServer) handleMCPPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, c.node.MCPPolicy())
}

func (c *controlAPIServer) handleMCPACLAllow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		Tool   string `json:"tool"`
		PubKey string `json:"pubkey"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	if err := c.node.AllowMCPToolCaller(req.Tool, req.PubKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func (c *controlAPIServer) handleMCPACLDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		Tool   string `json:"tool"`
		PubKey string `json:"pubkey"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	ok := c.node.DenyMCPToolCaller(req.Tool, req.PubKey)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok})
}

func (c *controlAPIServer) handleMCPACLClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		Tool string `json:"tool"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	ok := c.node.ClearMCPToolACL(req.Tool)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok})
}

func (c *controlAPIServer) handleMCPACLDefault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		DefaultDeny bool `json:"default_deny"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	if err := c.node.SetMCPACLDefaultDeny(req.DefaultDeny); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "default_deny": req.DefaultDeny})
}

func (c *controlAPIServer) handleMCPRate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		Tool      string `json:"tool"`
		Limit     int    `json:"limit"`
		WindowSec int64  `json:"window_sec"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	window := time.Duration(req.WindowSec) * time.Second
	if strings.TrimSpace(req.Tool) == "" || strings.TrimSpace(req.Tool) == "*" {
		if err := c.node.SetMCPDefaultRateLimit(req.Limit, window); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "scope": "default"})
		return
	}
	if err := c.node.SetMCPToolRateLimit(req.Tool, req.Limit, window); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "scope": "tool"})
}

func (c *controlAPIServer) handleMCPRateClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		Tool string `json:"tool"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	ok := c.node.ClearMCPToolRateLimit(req.Tool)
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok})
}

func (c *controlAPIServer) handleInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), 20, 500)
	items, err := c.node.InboxEvents(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(items), "items": items})
}

func (c *controlAPIServer) handleInboxUnread(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), 20, 500)
	items, err := c.node.UnreadInboxEvents(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(items), "items": items})
}

func (c *controlAPIServer) handleInboxAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"error": "method not allowed"})
		return
	}
	var req struct {
		EventID string `json:"event_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": err.Error()})
		return
	}
	eventID := strings.TrimSpace(req.EventID)
	if eventID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "event_id is required"})
		return
	}
	ok, err := c.node.AckInboxEvent(eventID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": ok, "event_id": eventID})
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseLimit(raw string, fallback int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > max {
		return max
	}
	return n
}
