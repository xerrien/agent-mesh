package agent

import (
	"sort"
	"strings"
)

func extractTaskLookup(payload interface{}) (string, bool) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return "", false
	}
	raw, ok := m["task"]
	if !ok {
		return "", false
	}
	task, ok := raw.(string)
	if !ok {
		return "", false
	}
	task = strings.TrimSpace(task)
	return task, task != ""
}

func extractProviderList(payload interface{}) []string {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := m["providers"]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{})
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, exists := seen[s]; exists {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (n *AgentNode) findProvidersForTask(task string) []string {
	task = strings.ToLower(strings.TrimSpace(task))
	if task == "" {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for peerID, cap := range n.peerCapabilities {
		if capabilityMatchesTask(cap, task) {
			seen[peerID] = struct{}{}
			out = append(out, peerID)
		}
	}
	for _, cap := range n.localCapabilities {
		if capabilityMatchesTask(cap, task) {
			if _, ok := seen[n.nodeID]; !ok {
				out = append(out, n.nodeID)
				seen[n.nodeID] = struct{}{}
			}
		}
	}
	sort.Strings(out)
	return out
}

func capabilityMatchesTask(cap AgentCapability, task string) bool {
	name := strings.ToLower(strings.TrimSpace(cap.Name))
	desc := strings.ToLower(strings.TrimSpace(cap.Description))
	if strings.Contains(name, task) || strings.Contains(desc, task) {
		return true
	}
	for _, token := range strings.Fields(task) {
		if token == "" {
			continue
		}
		if strings.Contains(name, token) || strings.Contains(desc, token) {
			return true
		}
	}
	return false
}
