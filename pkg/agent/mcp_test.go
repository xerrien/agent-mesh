package agent

import (
	"context"
	"errors"
	"testing"
)

func TestMCPAdapterRegisterAndCall(t *testing.T) {
	t.Parallel()

	m := NewMCPAdapter("")
	if err := m.RegisterTool("local.echo", "echo", func(_ context.Context, args map[string]interface{}) (interface{}, error) {
		return args, nil
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	out, err := m.CallTool(context.Background(), "local.echo", map[string]interface{}{"x": 1.0})
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}
	mm, ok := out.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result")
	}
	if v, ok := mm["x"].(float64); !ok || v != 1.0 {
		t.Fatalf("expected x=1")
	}
	if m.SchemaHash() == "" {
		t.Fatalf("expected non-empty schema hash")
	}
	if d := m.Descriptor(); d == nil || len(d.Tools) == 0 {
		t.Fatalf("expected descriptor with tools")
	}
}

func TestParseMCPInvocation(t *testing.T) {
	t.Parallel()

	tool, args, ok, err := parseMCPInvocation(`{"tool":"workspace.search","args":{"tag":"go"}}`)
	if err != nil || !ok {
		t.Fatalf("expected valid direct invocation, err=%v", err)
	}
	if tool != "workspace.search" {
		t.Fatalf("unexpected tool: %s", tool)
	}
	if _, ok := args["tag"]; !ok {
		t.Fatalf("expected args.tag")
	}

	tool, _, ok, err = parseMCPInvocation(`{"mcp":{"tool":"local.echo","args":{"x":1}}}`)
	if err != nil || !ok || tool != "local.echo" {
		t.Fatalf("expected valid nested invocation, tool=%s err=%v", tool, err)
	}

	_, _, ok, err = parseMCPInvocation(`hello`)
	if err != nil || ok {
		t.Fatalf("expected plain text to be non-invocation")
	}
}

func TestMCPAdapterValidator(t *testing.T) {
	t.Parallel()

	m := NewMCPAdapter("")
	if err := m.RegisterToolWithValidator("local.validated", "validated", func(args map[string]interface{}) error {
		v, ok := args["x"].(float64)
		if !ok || v <= 0 {
			return errors.New("x must be > 0")
		}
		return nil
	}, func(_ context.Context, args map[string]interface{}) (interface{}, error) {
		return args, nil
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}

	if _, err := m.CallTool(context.Background(), "local.validated", map[string]interface{}{"x": 0.0}); err == nil {
		t.Fatalf("expected validator error")
	}
	if _, err := m.CallTool(context.Background(), "local.validated", map[string]interface{}{"x": 1.0}); err != nil {
		t.Fatalf("expected valid args, got %v", err)
	}
}
