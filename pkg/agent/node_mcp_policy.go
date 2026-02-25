package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const defaultMCPIdempotencyTTL = 10 * time.Minute
const mcpCacheGCInterval = 60 * time.Second

type mcpRateLimitPolicy struct {
	Limit  int
	Window time.Duration
}

type mcpRateBucket struct {
	WindowStart time.Time
	Count       int
}

type mcpExecutionCache struct {
	ExpiresAt time.Time
	Result    interface{}
	Err       string
}

type MCPRatePolicy struct {
	Tool      string `json:"tool"`
	Limit     int    `json:"limit"`
	WindowSec int64  `json:"window_sec"`
}

type MCPPolicySnapshot struct {
	DefaultRate    MCPRatePolicy       `json:"default_rate"`
	ToolRates      []MCPRatePolicy     `json:"tool_rates"`
	ToolACL        map[string][]string `json:"tool_acl"`
	ACLDefaultDeny bool                `json:"acl_default_deny"`
}

func normalizeToolName(tool string) (string, error) {
	tool = strings.TrimSpace(strings.ToLower(tool))
	if tool == "" {
		return "", fmt.Errorf("tool cannot be empty")
	}
	return tool, nil
}

func (n *AgentNode) SetMCPDefaultRateLimit(limit int, window time.Duration) error {
	if limit <= 0 {
		return fmt.Errorf("limit must be > 0")
	}
	if window <= 0 {
		return fmt.Errorf("window must be > 0")
	}
	if n.Memory != nil {
		if err := n.Memory.SaveMCPDefaultRate(limit, int64(window/time.Second)); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.mcpDefaultRate = mcpRateLimitPolicy{Limit: limit, Window: window}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) SetMCPToolRateLimit(tool string, limit int, window time.Duration) error {
	tool, err := normalizeToolName(tool)
	if err != nil {
		return err
	}
	if limit <= 0 {
		return fmt.Errorf("limit must be > 0")
	}
	if window <= 0 {
		return fmt.Errorf("window must be > 0")
	}
	if n.Memory != nil {
		if err := n.Memory.SaveMCPToolRate(tool, limit, int64(window/time.Second)); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.mcpToolRateLimits[tool] = mcpRateLimitPolicy{Limit: limit, Window: window}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) ClearMCPToolRateLimit(tool string) bool {
	tool, err := normalizeToolName(tool)
	if err != nil {
		return false
	}
	if n.Memory != nil {
		_ = n.Memory.DeleteMCPToolRate(tool)
	}
	n.mu.Lock()
	_, ok := n.mcpToolRateLimits[tool]
	delete(n.mcpToolRateLimits, tool)
	n.mu.Unlock()
	return ok
}

func (n *AgentNode) AllowMCPToolCaller(tool string, peerID string) error {
	tool, err := normalizeToolName(tool)
	if err != nil {
		return err
	}
	peerID, err = normalizePubKey(peerID)
	if err != nil {
		return err
	}
	if n.Memory != nil {
		if err := n.Memory.SaveMCPToolACL(tool, peerID); err != nil {
			return err
		}
	}
	n.mu.Lock()
	acl := n.mcpToolACL[tool]
	if acl == nil {
		acl = make(map[string]struct{})
		n.mcpToolACL[tool] = acl
	}
	acl[peerID] = struct{}{}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) DenyMCPToolCaller(tool string, peerID string) bool {
	tool, err := normalizeToolName(tool)
	if err != nil {
		return false
	}
	peerID, err = normalizePubKey(peerID)
	if err != nil {
		return false
	}
	if n.Memory != nil {
		_ = n.Memory.DeleteMCPToolACL(tool, peerID)
	}
	n.mu.Lock()
	acl := n.mcpToolACL[tool]
	if acl == nil {
		n.mu.Unlock()
		return false
	}
	_, ok := acl[peerID]
	delete(acl, peerID)
	if len(acl) == 0 {
		delete(n.mcpToolACL, tool)
	}
	n.mu.Unlock()
	return ok
}

func (n *AgentNode) ClearMCPToolACL(tool string) bool {
	tool, err := normalizeToolName(tool)
	if err != nil {
		return false
	}
	if n.Memory != nil {
		_ = n.Memory.DeleteAllMCPToolACL(tool)
	}
	n.mu.Lock()
	_, ok := n.mcpToolACL[tool]
	delete(n.mcpToolACL, tool)
	n.mu.Unlock()
	return ok
}

func (n *AgentNode) MCPPolicy() MCPPolicySnapshot {
	n.mu.RLock()
	defer n.mu.RUnlock()

	out := MCPPolicySnapshot{
		DefaultRate: MCPRatePolicy{
			Tool:      "*",
			Limit:     n.mcpDefaultRate.Limit,
			WindowSec: int64(n.mcpDefaultRate.Window / time.Second),
		},
		ToolRates:      make([]MCPRatePolicy, 0, len(n.mcpToolRateLimits)),
		ToolACL:        make(map[string][]string, len(n.mcpToolACL)),
		ACLDefaultDeny: n.mcpACLDefaultDeny,
	}
	for tool, policy := range n.mcpToolRateLimits {
		out.ToolRates = append(out.ToolRates, MCPRatePolicy{
			Tool:      tool,
			Limit:     policy.Limit,
			WindowSec: int64(policy.Window / time.Second),
		})
	}
	sort.Slice(out.ToolRates, func(i, j int) bool { return out.ToolRates[i].Tool < out.ToolRates[j].Tool })
	for tool, peers := range n.mcpToolACL {
		list := make([]string, 0, len(peers))
		for p := range peers {
			list = append(list, p)
		}
		sort.Strings(list)
		out.ToolACL[tool] = list
	}
	return out
}

func (n *AgentNode) SetMCPACLDefaultDeny(defaultDeny bool) error {
	if n.Memory != nil {
		if err := n.Memory.SaveMCPACLDefaultDeny(defaultDeny); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.mcpACLDefaultDeny = defaultDeny
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) MCPACLDefaultDeny() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.mcpACLDefaultDeny
}

func (n *AgentNode) mcpCallerAllowed(tool string, requester string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	acl := n.mcpToolACL[tool]
	if len(acl) == 0 {
		return !n.mcpACLDefaultDeny
	}
	_, ok := acl[requester]
	return ok
}

func (n *AgentNode) mcpRateAllowed(tool string, requester string) (bool, time.Duration) {
	now := time.Now()

	n.mu.Lock()
	defer n.mu.Unlock()

	policy := n.mcpDefaultRate
	if custom, ok := n.mcpToolRateLimits[tool]; ok {
		policy = custom
	}
	if policy.Limit <= 0 || policy.Window <= 0 {
		return true, 0
	}

	key := requester + "|" + tool
	bucket := n.mcpRateBuckets[key]
	if bucket.WindowStart.IsZero() || now.Sub(bucket.WindowStart) >= policy.Window {
		bucket.WindowStart = now
		bucket.Count = 0
	}
	if bucket.Count >= policy.Limit {
		retryIn := policy.Window - now.Sub(bucket.WindowStart)
		if retryIn < 0 {
			retryIn = 0
		}
		n.mcpRateBuckets[key] = bucket
		return false, retryIn
	}
	bucket.Count++
	n.mcpRateBuckets[key] = bucket
	return true, 0
}

func (n *AgentNode) mcpCacheKey(requester string, tool string, requestID string) string {
	return requester + "|" + tool + "|" + requestID
}

func (n *AgentNode) mcpCacheGet(requester string, tool string, requestID string) (mcpExecutionCache, bool) {
	key := n.mcpCacheKey(requester, tool, requestID)

	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	v, ok := n.mcpExecCache[key]
	if !ok || now.After(v.ExpiresAt) {
		if ok {
			delete(n.mcpExecCache, key)
		}
		return mcpExecutionCache{}, false
	}
	return v, true
}

func (n *AgentNode) mcpCachePut(requester string, tool string, requestID string, result interface{}, err error) {
	if strings.TrimSpace(requestID) == "" {
		return
	}
	cache := mcpExecutionCache{
		ExpiresAt: time.Now().Add(defaultMCPIdempotencyTTL),
		Result:    result,
	}
	if err != nil {
		cache.Err = err.Error()
	}
	key := n.mcpCacheKey(requester, tool, requestID)
	n.mu.Lock()
	n.mcpExecCache[key] = cache
	if n.mcpCacheLastGC.IsZero() || time.Since(n.mcpCacheLastGC) >= mcpCacheGCInterval {
		now := time.Now()
		for k, v := range n.mcpExecCache {
			if now.After(v.ExpiresAt) {
				delete(n.mcpExecCache, k)
			}
		}
		n.mcpCacheLastGC = now
	}
	n.mu.Unlock()
}

func (n *AgentNode) executeMCPToolForRequest(ctx context.Context, requester string, requestID string, tool string, args map[string]interface{}) (interface{}, bool, error) {
	if n.mcp == nil {
		return nil, false, fmt.Errorf("mcp adapter not initialized")
	}
	requester, err := normalizePubKey(requester)
	if err != nil {
		return nil, false, err
	}
	tool, err = normalizeToolName(tool)
	if err != nil {
		return nil, false, err
	}
	requestID = strings.TrimSpace(requestID)

	if !n.mcpToolAllowed(tool) {
		return nil, false, fmt.Errorf("mcp tool not allowed by local capability map: %s", tool)
	}
	if !n.mcpCallerAllowed(tool, requester) {
		return nil, false, fmt.Errorf("mcp caller not allowed for tool %s", tool)
	}
	if requestID != "" {
		if cached, ok := n.mcpCacheGet(requester, tool, requestID); ok {
			if cached.Err != "" {
				return nil, true, fmt.Errorf("%s", cached.Err)
			}
			return cached.Result, true, nil
		}
	}

	allowed, retryIn := n.mcpRateAllowed(tool, requester)
	if !allowed {
		return nil, false, fmt.Errorf("mcp rate limit exceeded for tool %s; retry in %s", tool, retryIn.Round(time.Second))
	}

	result, callErr := n.mcp.CallTool(ctx, tool, args)
	n.mcpCachePut(requester, tool, requestID, result, callErr)
	if callErr != nil {
		return nil, false, callErr
	}
	return result, false, nil
}

func (n *AgentNode) loadMCPPolicyFromStore() error {
	if n.Memory == nil {
		return nil
	}
	if limit, windowSec, ok, err := n.Memory.GetMCPDefaultRate(); err != nil {
		return err
	} else if ok && limit > 0 && windowSec > 0 {
		n.mu.Lock()
		n.mcpDefaultRate = mcpRateLimitPolicy{
			Limit:  limit,
			Window: time.Duration(windowSec) * time.Second,
		}
		n.mu.Unlock()
	}

	toolRates, err := n.Memory.ListMCPToolRates()
	if err != nil {
		return err
	}
	n.mu.Lock()
	for _, p := range toolRates {
		if p.Limit <= 0 || p.WindowSec <= 0 {
			continue
		}
		n.mcpToolRateLimits[strings.TrimSpace(strings.ToLower(p.Tool))] = mcpRateLimitPolicy{
			Limit:  p.Limit,
			Window: time.Duration(p.WindowSec) * time.Second,
		}
	}
	n.mu.Unlock()

	aclMap, err := n.Memory.ListMCPToolACL()
	if err != nil {
		return err
	}
	n.mu.Lock()
	for tool, peers := range aclMap {
		t := strings.TrimSpace(strings.ToLower(tool))
		if t == "" {
			continue
		}
		acl := n.mcpToolACL[t]
		if acl == nil {
			acl = make(map[string]struct{})
			n.mcpToolACL[t] = acl
		}
		for _, p := range peers {
			pk := strings.TrimSpace(strings.ToLower(p))
			if pk == "" {
				continue
			}
			acl[pk] = struct{}{}
		}
	}
	n.mu.Unlock()
	if defaultDeny, ok, err := n.Memory.GetMCPACLDefaultDeny(); err != nil {
		return err
	} else if ok {
		n.mu.Lock()
		n.mcpACLDefaultDeny = defaultDeny
		n.mu.Unlock()
	}
	return nil
}
