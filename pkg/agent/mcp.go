package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const maxMCPToolNameLength = 128

type MCPToolHandler func(ctx context.Context, args map[string]interface{}) (interface{}, error)
type MCPToolValidator func(args map[string]interface{}) error

type MCPTool struct {
	Info      MCPToolInfo
	Handler   MCPToolHandler
	Validator MCPToolValidator
}

type MCPAdapter struct {
	mu       sync.RWMutex
	endpoint string
	tools    map[string]MCPTool
}

func NewMCPAdapter(endpoint string) *MCPAdapter {
	if strings.TrimSpace(endpoint) == "" {
		endpoint = "local://agentswarm/mcp"
	}
	return &MCPAdapter{
		endpoint: strings.TrimSpace(endpoint),
		tools:    make(map[string]MCPTool),
	}
}

func (m *MCPAdapter) RegisterTool(name string, description string, handler MCPToolHandler) error {
	return m.RegisterToolWithValidator(name, description, nil, handler)
}

func (m *MCPAdapter) RegisterToolWithValidator(name string, description string, validator MCPToolValidator, handler MCPToolHandler) error {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}
	if len(name) > maxMCPToolNameLength {
		return fmt.Errorf("tool name too long (max %d)", maxMCPToolNameLength)
	}
	if handler == nil {
		return fmt.Errorf("tool handler cannot be nil")
	}
	m.mu.Lock()
	m.tools[name] = MCPTool{
		Info: MCPToolInfo{
			Name:        name,
			Description: strings.TrimSpace(description),
		},
		Handler:   handler,
		Validator: validator,
	}
	m.mu.Unlock()
	return nil
}

func (m *MCPAdapter) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return nil, fmt.Errorf("tool name cannot be empty")
	}
	if len(name) > maxMCPToolNameLength {
		return nil, fmt.Errorf("tool name too long (max %d)", maxMCPToolNameLength)
	}
	m.mu.RLock()
	tool, ok := m.tools[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown MCP tool: %s", name)
	}
	if args == nil {
		args = map[string]interface{}{}
	}
	if tool.Validator != nil {
		if err := tool.Validator(args); err != nil {
			return nil, err
		}
	}
	return tool.Handler(ctx, args)
}

func (m *MCPAdapter) ToolInfos() []MCPToolInfo {
	m.mu.RLock()
	out := make([]MCPToolInfo, 0, len(m.tools))
	for _, t := range m.tools {
		out = append(out, t.Info)
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *MCPAdapter) SchemaHash() string {
	tools := m.ToolInfos()
	body, err := json.Marshal(tools)
	if err != nil {
		sum := sha256.Sum256([]byte("schema-error"))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (m *MCPAdapter) Descriptor() *MCPDescriptor {
	return &MCPDescriptor{
		Endpoint:   m.endpoint,
		SchemaHash: m.SchemaHash(),
		Tools:      m.ToolInfos(),
	}
}





