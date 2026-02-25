package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) subscribeRelay(relay *nostr.Relay) {
	filter := nostr.Filter{
		Kinds: []nostr.Kind{KindCapability, KindKnowledgeQuery, KindTaskRequest, KindTaskResponse},
		Tags:  nostr.TagMap{meshTagName: []string{meshTagValue}},
	}
	if ts, eventID, err := n.Memory.GetRelayCursor(relay.URL); err == nil && ts > 0 {
		filter.Since = nostr.Timestamp(ts + 1)
		if eventID != "" {
			fmt.Printf("[Backfill] Relay %s since %d (last=%s)\n", relay.URL, ts+1, eventID)
		} else {
			fmt.Printf("[Backfill] Relay %s since %d\n", relay.URL, ts+1)
		}
	}
	sub, err := relay.Subscribe(n.ctx, filter, nostr.SubscriptionOptions{})
	if err != nil {
		fmt.Printf("[Nostr] Subscribe failed on %s: %v\n", relay.URL, err)
		return
	}

	for evt := range sub.Events {
		if evt.PubKey.Hex() == n.NodeID() {
			continue
		}
		n.addPeerRelay(evt.PubKey.Hex(), relay.URL)
		n.persistInboxEvent(relay.URL, evt)
		if n.seen(evt.ID) {
			n.updateRelayCursor(relay.URL, evt)
			continue
		}
		n.handleEvent(evt)
		n.updateRelayCursor(relay.URL, evt)
	}
}

func (n *AgentNode) handleEvent(evt nostr.Event) {
	switch evt.Kind {
	case KindCapability:
		n.handleCapabilityEvent(evt)
	case KindKnowledgeQuery:
		n.handleKnowledgeQueryEvent(evt)
	case KindTaskRequest:
		n.handleTaskRequestEvent(evt)
	case KindTaskResponse:
		n.handleTaskResponseEvent(evt)
	}
}

func (n *AgentNode) handleCapabilityEvent(evt nostr.Event) {
	var data struct {
		Capability AgentCapability `json:"capability"`
		EthAddress string          `json:"ethAddress,omitempty"`
	}
	if err := json.Unmarshal([]byte(evt.Content), &data); err != nil {
		return
	}

	peerID := evt.PubKey.Hex()
	n.mu.Lock()
	n.knownPeers[peerID] = struct{}{}
	n.peerCapabilities[peerID] = data.Capability
	checker := n.reputationChecker
	callbacks := append([]CapabilityCallback(nil), n.onCapCallbacks...)
	n.mu.Unlock()

	if checker != nil && data.EthAddress != "" {
		ok, err := checker(peerID, data.EthAddress)
		if err != nil || !ok {
			return
		}
	}

	for _, cb := range callbacks {
		cb(peerID, data.Capability)
	}
}

func (n *AgentNode) handleKnowledgeQueryEvent(evt nostr.Event) {
	var query KnowledgeDiscoveryMsg
	if err := json.Unmarshal([]byte(evt.Content), &query); err != nil {
		return
	}
	fmt.Printf("[Memory] Received discovery query: %q from %s\n", query.Query, query.Requester)

	var matches []MemoryChunk
	n.Memory.mu.RLock()
	for _, tag := range query.Tags {
		items, err := n.Memory.Search(tag)
		if err == nil {
			matches = append(matches, items...)
		}
	}
	n.Memory.mu.RUnlock()
	if len(matches) > 0 {
		fmt.Printf("[Memory] Found %d potential matches for %q\n", len(matches), query.Query)
	}
	n.triggerWakeHook("knowledge_query", evt.PubKey.Hex())
}

func (n *AgentNode) handleTaskRequestEvent(evt nostr.Event) {
	targetTag := evt.Tags.Find("p")
	if targetTag == nil || len(targetTag) < 2 || targetTag[1] != n.NodeID() {
		return
	}

	var msg AgentMessage
	if err := json.Unmarshal([]byte(evt.Content), &msg); err != nil {
		return
	}

	reqTag := evt.Tags.Find("req")
	if reqTag == nil || len(reqTag) < 2 {
		return
	}
	fromTag := evt.Tags.Find("from")
	if fromTag == nil || len(fromTag) < 2 {
		return
	}
	requester := fromTag[1]
	if _, err := nostr.PubKeyFromHex(requester); err != nil {
		return
	}

	n.mu.Lock()
	n.knownPeers[requester] = struct{}{}
	n.mu.Unlock()

	respPayload, handled := n.dispatchMessageHandler(n.ctx, MessageRequest{
		Requester: requester,
		Message:   msg,
		Event:     evt,
	})
	if !handled {
		return
	}

	resp := AgentMessage{
		Type:      MessageTypeResponse,
		Payload:   respPayload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}

	tags := nostr.Tags{
		nostr.Tag{"p", requester},
		nostr.Tag{"req", reqTag[1]},
		nostr.Tag{"from", n.NodeID()},
	}
	_ = n.publishJSONEvent(KindTaskResponse, tags, resp)
}

func (n *AgentNode) handleTaskResponseEvent(evt nostr.Event) {
	targetTag := evt.Tags.Find("p")
	if targetTag == nil || len(targetTag) < 2 || targetTag[1] != n.NodeID() {
		return
	}
	reqTag := evt.Tags.Find("req")
	if reqTag == nil || len(reqTag) < 2 {
		return
	}

	var msg AgentMessage
	if err := json.Unmarshal([]byte(evt.Content), &msg); err != nil {
		return
	}
	n.mu.Lock()
	n.knownPeers[evt.PubKey.Hex()] = struct{}{}
	ch := n.pendingTasks[reqTag[1]]
	n.mu.Unlock()

	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}
