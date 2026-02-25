package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"fiatjaf.com/nostr"
)

func ensureMeshTag(tags nostr.Tags) nostr.Tags {
	for _, t := range tags {
		if len(t) >= 2 && t[0] == meshTagName && t[1] == meshTagValue {
			return tags
		}
	}
	return append(tags, nostr.Tag{meshTagName, meshTagValue})
}

func (n *AgentNode) publishJSONEvent(kind nostr.Kind, tags nostr.Tags, payload interface{}) error {
	evt, relays, err := n.buildSignedEvent(kind, tags, payload)
	if err != nil {
		return err
	}
	okCount, errs := n.publishEventToRelays(evt, relays)
	if okCount == 0 {
		return fmt.Errorf("publish failed on all relays: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *AgentNode) publishJSONEventForPeer(kind nostr.Kind, tags nostr.Tags, payload interface{}, peerID string) error {
	evt, allRelays, err := n.buildSignedEvent(kind, tags, payload)
	if err != nil {
		return err
	}

	n.mu.RLock()
	peerRelayURLs := append([]string(nil), n.peerRelays[peerID]...)
	n.mu.RUnlock()

	return n.publishToPreferredRelays(evt, allRelays, peerRelayURLs)
}

func (n *AgentNode) buildSignedEvent(kind nostr.Kind, tags nostr.Tags, payload interface{}) (nostr.Event, []relayClient, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nostr.Event{}, nil, err
	}
	tags = ensureMeshTag(tags)
	evt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      kind,
		Tags:      tags,
		Content:   string(body),
	}
	n.mu.RLock()
	sk := n.secretKey
	relays := append([]relayClient(nil), n.relays...)
	n.mu.RUnlock()
	if err := evt.Sign(sk); err != nil {
		return nostr.Event{}, nil, err
	}
	return evt, relays, nil
}

func (n *AgentNode) publishToPreferredRelays(evt nostr.Event, allRelays []relayClient, preferredURLs []string) error {
	if len(allRelays) == 0 {
		return fmt.Errorf("no connected relays")
	}

	primary, secondary := splitRelaysByURLs(allRelays, preferredURLs)
	if len(primary) == 0 {
		okCount, errs := n.publishEventToRelays(evt, allRelays)
		if okCount == 0 {
			return fmt.Errorf("publish failed on all relays: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	okPrimary, errsPrimary := n.publishEventToRelays(evt, primary)
	if okPrimary > 0 {
		return nil
	}
	okFallback, errsFallback := n.publishEventToRelays(evt, secondary)
	if okFallback > 0 {
		return nil
	}

	combined := append(errsPrimary, errsFallback...)
	return fmt.Errorf("publish failed on peer relays and fallback relays: %s", strings.Join(combined, "; "))
}

func (n *AgentNode) publishEventToRelays(evt nostr.Event, relays []relayClient) (int, []string) {
	if len(relays) == 0 {
		return 0, []string{"no connected relays"}
	}
	var wg sync.WaitGroup
	var okCount int
	var errMu sync.Mutex
	errs := make([]string, 0, len(relays))
	for _, relay := range relays {
		wg.Add(1)
		go func(r relayClient) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, relayPublishTimeout)
			defer cancel()
			if err := r.Publish(ctx, evt); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", r.URL(), err))
				errMu.Unlock()
				return
			}
			errMu.Lock()
			okCount++
			errMu.Unlock()
		}(relay)
	}
	wg.Wait()
	return okCount, errs
}

func splitRelaysByURLs(relays []relayClient, urls []string) ([]relayClient, []relayClient) {
	if len(relays) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		allowed[u] = struct{}{}
	}
	primary := make([]relayClient, 0, len(relays))
	secondary := make([]relayClient, 0, len(relays))
	for _, r := range relays {
		if r == nil {
			continue
		}
		if _, ok := allowed[r.URL()]; ok {
			primary = append(primary, r)
		} else {
			secondary = append(secondary, r)
		}
	}
	return primary, secondary
}

func (n *AgentNode) addPeerRelay(peerID string, relayURL string) {
	peerID = strings.TrimSpace(peerID)
	relayURL = strings.TrimSpace(relayURL)
	if peerID == "" || relayURL == "" {
		return
	}
	if _, err := normalizePubKey(peerID); err != nil {
		return
	}
	if !strings.HasPrefix(relayURL, "ws://") && !strings.HasPrefix(relayURL, "wss://") {
		return
	}
	n.mu.Lock()
	current := append([]string(nil), n.peerRelays[peerID]...)
	current = append(current, relayURL)
	n.peerRelays[peerID] = parseRelayURLs(strings.Join(current, ","))
	n.mu.Unlock()
}
