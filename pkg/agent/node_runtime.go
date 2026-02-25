package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) loadOrCreateKey() (nostr.SecretKey, error) {
	keyPath := filepath.Join(n.workspace, identityKeyFileName)
	if b, err := os.ReadFile(keyPath); err == nil {
		hexKey := strings.TrimSpace(string(b))
		sk, err := nostr.SecretKeyFromHex(hexKey)
		if err == nil {
			fmt.Printf("[Identity] Loaded existing key from %s\n", keyPath)
			return sk, nil
		}
	}

	sk := nostr.Generate()
	if err := os.WriteFile(keyPath, []byte(sk.Hex()), 0600); err != nil {
		fmt.Printf("[Identity] Warning: could not save key to %s: %v\n", keyPath, err)
	} else {
		fmt.Printf("[Identity] Generated new key, saved to %s\n", keyPath)
	}
	return sk, nil
}

func (n *AgentNode) logNetworkHealth() {
	ticker := time.NewTicker(networkHealthLogInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.mu.RLock()
			relayCount := len(n.relays)
			peerCount := len(n.knownPeers)
			n.mu.RUnlock()
			fmt.Printf("[Network] Connected relays: %d | Known peers: %d\n", relayCount, peerCount)
		case <-n.ctx.Done():
			return
		}
	}
}

func parseRelayURLs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		u := strings.TrimSpace(p)
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "ws://") && !strings.HasPrefix(u, "wss://") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func loadWakeHookConfig() (string, time.Duration, time.Duration) {
	cmd := strings.TrimSpace(os.Getenv("AGENTMESH_WAKE_HOOK"))
	if cmd == "" {
		return "", 0, 0
	}
	cooldown := 15 * time.Second
	if raw := strings.TrimSpace(os.Getenv("AGENTMESH_WAKE_HOOK_COOLDOWN")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			cooldown = d
		}
	}
	timeout := 8 * time.Second
	if raw := strings.TrimSpace(os.Getenv("AGENTMESH_WAKE_HOOK_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			timeout = d
		}
	}
	return cmd, cooldown, timeout
}

func (n *AgentNode) triggerWakeHook(reason string, sender string) {
	n.mu.Lock()
	cmd := n.wakeHookCommand
	cooldown := n.wakeHookCooldown
	timeout := n.wakeHookTimeout
	if cmd == "" {
		n.mu.Unlock()
		return
	}
	now := time.Now()
	if !n.lastWakeHook.IsZero() && cooldown > 0 && now.Sub(n.lastWakeHook) < cooldown {
		n.mu.Unlock()
		return
	}
	n.lastWakeHook = now
	n.mu.Unlock()

	go n.runWakeHook(cmd, timeout, reason, sender)
}

func (n *AgentNode) runWakeHook(command string, timeout time.Duration, reason string, sender string) {
	ctx, cancel := context.WithTimeout(n.ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}
	cmd.Env = append(os.Environ(),
		"AGENTMESH_WAKE_REASON="+reason,
		"AGENTMESH_WAKE_SENDER="+sender,
		"AGENTMESH_WAKE_NODE="+n.NodeID(),
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			fmt.Printf("[WakeHook] Failed (%s): %v\n", reason, err)
			return
		}
		fmt.Printf("[WakeHook] Failed (%s): %v | %s\n", reason, err, msg)
		return
	}
	if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
		fmt.Printf("[WakeHook] Triggered (%s): %s\n", reason, trimmed)
	}
}
