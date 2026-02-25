package agent

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

func extractPeerHints(payload interface{}) []PeerHint {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := m["peers"]
	if !ok {
		return nil
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var peers []PeerHint
	if err := json.Unmarshal(body, &peers); err != nil {
		return nil
	}
	out := make([]PeerHint, 0, len(peers))
	for _, p := range peers {
		if _, err := normalizePubKey(p.PubKey); err != nil {
			continue
		}
		p.Relays = parseRelayURLs(strings.Join(p.Relays, ","))
		p.Capabilities = uniqueStrings(p.Capabilities)
		out = append(out, p)
	}
	return out
}

func (n *AgentNode) buildPeerHints(limit int) []PeerHint {
	if limit <= 0 {
		limit = 64
	}
	if limit > 256 {
		limit = 256
	}

	n.mu.RLock()
	defer n.mu.RUnlock()

	peerIDs := make([]string, 0, len(n.knownPeers)+1)
	for id := range n.knownPeers {
		peerIDs = append(peerIDs, id)
	}
	sort.Strings(peerIDs)

	out := make([]PeerHint, 0, limit)
	selfCaps := make([]string, 0, len(n.localCapabilities))
	for _, cap := range n.localCapabilities {
		if name := strings.TrimSpace(cap.Name); name != "" {
			selfCaps = append(selfCaps, name)
		}
	}
	self := PeerHint{
		PubKey:       n.nodeID,
		Relays:       append([]string(nil), n.relayURLs...),
		Capabilities: uniqueStrings(selfCaps),
		LastSeenAt:   time.Now().UnixMilli(),
	}
	out = append(out, self)
	if len(out) >= limit {
		return out
	}

	for _, id := range peerIDs {
		hint := PeerHint{
			PubKey:     id,
			LastSeenAt: time.Now().UnixMilli(),
		}
		if cap, ok := n.peerCapabilities[id]; ok {
			if name := strings.TrimSpace(cap.Name); name != "" {
				hint.Capabilities = []string{name}
			}
		}
		if relays, ok := n.peerRelays[id]; ok && len(relays) > 0 {
			hint.Relays = append([]string(nil), relays...)
		}
		out = append(out, hint)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (n *AgentNode) ingestPeerHints(peers []PeerHint) {
	if len(peers) == 0 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, p := range peers {
		pub, err := normalizePubKey(p.PubKey)
		if err != nil || pub == n.nodeID {
			continue
		}
		n.knownPeers[pub] = struct{}{}
		if len(p.Relays) > 0 {
			current := append([]string(nil), n.peerRelays[pub]...)
			current = append(current, p.Relays...)
			n.peerRelays[pub] = parseRelayURLs(strings.Join(current, ","))
		}
	}
}

func extractPositiveInt(payload interface{}, key string, fallback int, max int) int {
	if fallback <= 0 {
		fallback = 1
	}
	m, ok := payload.(map[string]interface{})
	if !ok {
		return fallback
	}
	raw, ok := m[key]
	if !ok {
		return fallback
	}
	var v int
	switch n := raw.(type) {
	case float64:
		v = int(n)
	case int:
		v = n
	case int64:
		v = int(n)
	default:
		return fallback
	}
	if v <= 0 {
		return fallback
	}
	if max > 0 && v > max {
		return max
	}
	return v
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
