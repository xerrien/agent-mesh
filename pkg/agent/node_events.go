package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) subscribeRelay(relay relayClient) {
	filter := nostr.Filter{
		Kinds: []nostr.Kind{KindCapability, KindTaskRequest, KindTaskResponse},
		Tags:  nostr.TagMap{meshTagName: []string{meshTagValue}},
	}
	if ts, eventID, err := n.Memory.GetRelayCursor(relay.URL()); err == nil && ts > 0 {
		filter.Since = nostr.Timestamp(ts + 1)
		if eventID != "" {
			fmt.Printf("[Backfill] Relay %s since %d (last=%s)\n", relay.URL(), ts+1, eventID)
		} else {
			fmt.Printf("[Backfill] Relay %s since %d\n", relay.URL(), ts+1)
		}
	}
	sub, err := relay.Subscribe(n.ctx, filter, nostr.SubscriptionOptions{})
	if err != nil {
		fmt.Printf("[Nostr] Subscribe failed on %s: %v\n", relay.URL(), err)
		return
	}

	for evt := range sub.Events {
		sender := evt.PubKey.Hex()
		if sender == n.NodeID() {
			continue
		}
		if n.IsBlockedPeer(sender) {
			n.updateRelayCursor(relay.URL(), evt)
			continue
		}
		n.addPeerRelay(sender, relay.URL())
		n.persistInboxEvent(relay.URL(), evt)
		if n.seen(evt.ID) {
			n.updateRelayCursor(relay.URL(), evt)
			continue
		}
		n.handleEvent(evt)
		n.updateRelayCursor(relay.URL(), evt)
	}
}

func (n *AgentNode) handleEvent(evt nostr.Event) {
	switch evt.Kind {
	case KindCapability:
		n.handleCapabilityEvent(evt)
	case KindTaskRequest:
		n.handleTaskRequestEvent(evt)
	case KindTaskResponse:
		n.handleTaskResponseEvent(evt)
	}
}

func (n *AgentNode) handleCapabilityEvent(evt nostr.Event) {
	if n.IsBlockedPeer(evt.PubKey.Hex()) {
		return
	}
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

func (n *AgentNode) handleTaskRequestEvent(evt nostr.Event) {
	if n.IsBlockedPeer(evt.PubKey.Hex()) {
		return
	}
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
	reqID := reqTag[1]
	fromTag := evt.Tags.Find("from")
	if fromTag == nil || len(fromTag) < 2 {
		return
	}
	requester := fromTag[1]
	if _, err := nostr.PubKeyFromHex(requester); err != nil {
		return
	}
	if requester != evt.PubKey.Hex() {
		return
	}
	if n.IsBlockedPeer(requester) {
		return
	}

	n.mu.Lock()
	n.knownPeers[requester] = struct{}{}
	n.mu.Unlock()

	_ = n.publishTaskResponse(requester, reqID, responsePayloadWithReceipt(
		ReceiptStageAccepted,
		reqID,
		"",
		"request accepted for processing",
		nil,
	))

	respPayload, handled := n.dispatchMessageHandler(n.ctx, MessageRequest{
		Requester: requester,
		Message:   msg,
		Event:     evt,
	})
	if !handled {
		detail := "no handler found for message type"
		if m, ok := respPayload["error"]; ok {
			if s, ok := m.(string); ok && s != "" {
				detail = s
			}
		}
		_ = n.publishTaskResponse(requester, reqID, responsePayloadWithReceipt(
			ReceiptStageFailed,
			reqID,
			"request_rejected",
			detail,
			nil,
		))
		return
	}

	_ = n.publishTaskResponse(requester, reqID, responsePayloadWithReceipt(
		ReceiptStageProcessed,
		reqID,
		"",
		"request processed",
		respPayload,
	))
}

func (n *AgentNode) handleTaskResponseEvent(evt nostr.Event) {
	if n.IsBlockedPeer(evt.PubKey.Hex()) {
		return
	}
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

func (n *AgentNode) publishTaskResponse(requester string, reqID string, payload interface{}) error {
	resp := AgentMessage{
		Type:      MessageTypeResponse,
		Payload:   payload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
		Meta: &MessageMeta{
			ReplyTo: reqID,
			Schema:  SchemaResponseV1,
			Purpose: "receipt",
		},
	}

	tags := nostr.Tags{
		nostr.Tag{"p", requester},
		nostr.Tag{"req", reqID},
		nostr.Tag{"from", n.NodeID()},
	}
	return n.publishJSONEvent(KindTaskResponse, tags, resp)
}
