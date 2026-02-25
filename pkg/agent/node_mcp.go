package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type mcpInvokeEnvelope struct {
	Tool string                 `json:"tool"`
	Args map[string]interface{} `json:"args"`
}

type mcpNestedEnvelope struct {
	MCP *mcpInvokeEnvelope `json:"mcp"`
}

func (n *AgentNode) initMCP() {
	n.mcp = NewMCPAdapter("local://agentswarm/mcp")

	_ = n.mcp.RegisterToolWithValidator("workspace.search", "Search local workspace memory by tag", func(args map[string]interface{}) error {
		rawTag, ok := args["tag"].(string)
		if !ok || strings.TrimSpace(rawTag) == "" {
			return fmt.Errorf("workspace.search requires non-empty tag")
		}
		return nil
	}, func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		rawTag, _ := args["tag"].(string)
		tag := strings.TrimSpace(rawTag)
		limit := 20
		if v, ok := args["limit"].(float64); ok && v > 0 {
			limit = int(v)
			if limit > 100 {
				limit = 100
			}
		}
		items, err := n.Memory.Search(tag)
		if err != nil {
			return nil, err
		}
		if len(items) > limit {
			items = items[:limit]
		}
		return map[string]interface{}{
			"tag":   tag,
			"count": len(items),
			"items": items,
		}, nil
	})

	_ = n.mcp.RegisterToolWithValidator("task.execute_hook", "Trigger wake hook for task execution", func(args map[string]interface{}) error {
		reason := "message"
		if r, ok := args["reason"].(string); ok && strings.TrimSpace(r) != "" {
			reason = strings.TrimSpace(r)
		}
		_ = reason
		if s, ok := args["sender"]; ok {
			if _, ok := s.(string); !ok {
				return fmt.Errorf("task.execute_hook sender must be a string")
			}
		}
		return nil
	}, func(_ context.Context, args map[string]interface{}) (interface{}, error) {
		reason := "message"
		if r, ok := args["reason"].(string); ok && strings.TrimSpace(r) != "" {
			reason = strings.TrimSpace(r)
		}
		sender := ""
		if s, ok := args["sender"].(string); ok {
			sender = strings.TrimSpace(s)
		}
		n.triggerWakeHook(reason, sender)
		return map[string]interface{}{
			"queued": true,
			"reason": reason,
		}, nil
	})

	_ = n.mcp.RegisterToolWithValidator("local.echo", "Echo arguments back for testing", func(map[string]interface{}) error {
		return nil
	}, func(_ context.Context, args map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{
			"echo": args,
			"at":   time.Now().UnixMilli(),
		}, nil
	})
}

func parseMCPInvocation(text string) (string, map[string]interface{}, bool, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", nil, false, nil
	}
	var direct mcpInvokeEnvelope
	if err := json.Unmarshal([]byte(text), &direct); err == nil && strings.TrimSpace(direct.Tool) != "" {
		return strings.TrimSpace(strings.ToLower(direct.Tool)), direct.Args, true, nil
	}
	var nested mcpNestedEnvelope
	if err := json.Unmarshal([]byte(text), &nested); err == nil && nested.MCP != nil && strings.TrimSpace(nested.MCP.Tool) != "" {
		return strings.TrimSpace(strings.ToLower(nested.MCP.Tool)), nested.MCP.Args, true, nil
	}
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		return "", nil, false, fmt.Errorf("invalid MCP invocation envelope")
	}
	return "", nil, false, nil
}

func mcpRequestID(req MessageRequest) string {
	if req.Message.Meta != nil {
		if id := strings.TrimSpace(req.Message.Meta.ID); id != "" {
			return id
		}
	}
	if reqTag := req.Event.Tags.Find("req"); reqTag != nil && len(reqTag) >= 2 {
		if id := strings.TrimSpace(reqTag[1]); id != "" {
			return id
		}
	}
	if id := strings.TrimSpace(req.Event.ID.String()); id != "" {
		return id
	}
	return ""
}

func (n *AgentNode) mcpToolAllowed(tool string) bool {
	tool = strings.TrimSpace(strings.ToLower(tool))
	n.mu.RLock()
	defer n.mu.RUnlock()
	haveDeclaredMCP := false
	for _, cap := range n.localCapabilities {
		if cap.MCP == nil || len(cap.MCP.Tools) == 0 {
			continue
		}
		haveDeclaredMCP = true
		for _, t := range cap.MCP.Tools {
			if strings.TrimSpace(strings.ToLower(t.Name)) == tool {
				return true
			}
		}
	}
	return !haveDeclaredMCP
}

func (n *AgentNode) executeMCPTool(ctx context.Context, tool string, args map[string]interface{}) (interface{}, error) {
	if n.mcp == nil {
		return nil, fmt.Errorf("mcp adapter not initialized")
	}
	if !n.mcpToolAllowed(tool) {
		return nil, fmt.Errorf("mcp tool not allowed by local capability map: %s", tool)
	}
	return n.mcp.CallTool(ctx, tool, args)
}

func (n *AgentNode) MCPDescriptor() *MCPDescriptor {
	if n.mcp == nil {
		return nil
	}
	return n.mcp.Descriptor()
}





