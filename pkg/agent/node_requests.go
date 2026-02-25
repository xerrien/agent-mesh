package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) SendTask(ctx context.Context, target string, payload interface{}) (interface{}, error) {
	msg := AgentMessage{
		Type:      MessageTypeTask,
		Payload:   payload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	return n.sendRequest(ctx, target, msg)
}

func (n *AgentNode) PingPeer(ctx context.Context, target string) error {
	msg := AgentMessage{
		Type:      MessageTypePing,
		Payload:   map[string]interface{}{"probe": "connect"},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	if _, err := n.sendRequest(ctx, target, msg); err != nil {
		legacy := AgentMessage{
			Type:      MessageTypeTask,
			Payload:   map[string]interface{}{"probe": "connect"},
			Sender:    n.NodeID(),
			Timestamp: time.Now().UnixMilli(),
		}
		if _, legacyErr := n.sendRequest(ctx, target, legacy); legacyErr != nil {
			return fmt.Errorf("peer did not acknowledge ping or legacy task probe: %w", err)
		}
	}
	peerID, err := normalizePubKey(target)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.knownPeers[peerID] = struct{}{}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) SendMessage(ctx context.Context, target string, text string) (interface{}, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("message cannot be empty")
	}
	peerID, err := normalizePubKey(target)
	if err != nil {
		return nil, err
	}
	ciphertext, err := n.encryptForPeer(peerID, text)
	if err != nil {
		return nil, err
	}
	msg := AgentMessage{
		Type:      MessageTypeMessage,
		Payload:   map[string]interface{}{"encoding": directMsgEncodingNIP44, "ciphertext": ciphertext},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	return n.sendRequest(ctx, peerID, msg)
}

func (n *AgentNode) QueryPeerForTaskProviders(ctx context.Context, target string, task string) ([]string, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return nil, fmt.Errorf("task cannot be empty")
	}
	msg := AgentMessage{
		Type:      MessageTypeProviderLookup,
		Payload:   map[string]interface{}{"task": task},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	resp, err := n.sendRequest(ctx, target, msg)
	if err != nil {
		return nil, err
	}
	return extractProviderList(resp), nil
}

func (n *AgentNode) QueryKnownPeersForTaskProviders(ctx context.Context, task string) ([]string, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return nil, fmt.Errorf("task cannot be empty")
	}
	peers := n.ConnectedPeers()
	unique := make(map[string]struct{})
	for _, peer := range peers {
		providers, err := n.QueryPeerForTaskProviders(ctx, peer, task)
		if err != nil {
			continue
		}
		for _, p := range providers {
			unique[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for p := range unique {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (n *AgentNode) RequestPeerExchange(ctx context.Context, target string, limit int) ([]PeerHint, error) {
	if limit <= 0 {
		limit = 64
	}
	msg := AgentMessage{
		Type: MessageTypePeerExchange,
		Payload: map[string]interface{}{
			"limit": limit,
		},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	resp, err := n.sendRequest(ctx, target, msg)
	if err != nil {
		return nil, err
	}
	peers := extractPeerHints(resp)
	n.ingestPeerHints(peers)
	return peers, nil
}

func (n *AgentNode) InboxEvents(limit int) ([]InboxEvent, error) {
	return n.Memory.ListInboxEvents(limit)
}

func (n *AgentNode) UnreadInboxEvents(limit int) ([]InboxEvent, error) {
	return n.Memory.ListUnreadInboxEvents(limit)
}

func (n *AgentNode) AckInboxEvent(eventID string) (bool, error) {
	return n.Memory.AckInboxEvent(eventID, n.NodeID())
}

func (n *AgentNode) sendRequest(ctx context.Context, target string, msg AgentMessage) (interface{}, error) {
	peerID, err := normalizePubKey(target)
	if err != nil {
		return nil, err
	}
	reqID := nostr.Generate().Hex()

	respCh := make(chan AgentMessage, 1)
	n.mu.Lock()
	n.pendingTasks[reqID] = respCh
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pendingTasks, reqID)
		n.mu.Unlock()
	}()

	tags := nostr.Tags{
		nostr.Tag{"p", peerID},
		nostr.Tag{"req", reqID},
		nostr.Tag{"from", n.NodeID()},
	}
	if err := n.publishJSONEventForPeer(KindTaskRequest, tags, msg, peerID); err != nil {
		return nil, err
	}

	select {
	case resp := <-respCh:
		n.mu.Lock()
		n.knownPeers[peerID] = struct{}{}
		n.mu.Unlock()
		return resp.Payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *AgentNode) dispatchMessageHandler(ctx context.Context, req MessageRequest) (map[string]interface{}, bool) {
	msgType := strings.TrimSpace(strings.ToLower(req.Message.Type))
	if msgType == "" {
		return nil, false
	}
	n.mu.RLock()
	handler := n.messageHandlers[msgType]
	n.mu.RUnlock()
	if handler == nil {
		return nil, false
	}
	resp, ok := handler(ctx, req)
	if !ok {
		return nil, false
	}
	if resp == nil {
		resp = make(map[string]interface{})
	}
	if _, exists := resp["status"]; !exists {
		resp["status"] = "success"
	}
	if _, exists := resp["agent"]; !exists {
		resp["agent"] = n.NodeID()
	}
	return resp, true
}

func (n *AgentNode) registerDefaultHandlers() {
	_ = n.RegisterHandler(MessageTypePing, func(_ context.Context, _ MessageRequest) (map[string]interface{}, bool) {
		return map[string]interface{}{
			"type": "pong",
		}, true
	})

	_ = n.RegisterHandler(MessageTypeMessage, func(_ context.Context, req MessageRequest) (map[string]interface{}, bool) {
		if text, ok := n.extractMessageTextForSender(req.Requester, req.Message.Payload); ok {
			fmt.Printf("[Message] %s: %s\n", req.Requester, text)
		}
		n.triggerWakeHook("message", req.Requester)
		return map[string]interface{}{
			"type":    "ack",
			"message": "delivered",
		}, true
	})

	_ = n.RegisterHandler(MessageTypeProviderLookup, func(_ context.Context, req MessageRequest) (map[string]interface{}, bool) {
		task, ok := extractTaskLookup(req.Message.Payload)
		if !ok {
			return nil, false
		}
		n.triggerWakeHook("provider_lookup", req.Requester)
		return map[string]interface{}{
			"type":      "providers",
			"task":      task,
			"providers": n.findProvidersForTask(task),
		}, true
	})

	_ = n.RegisterHandler(MessageTypeTask, func(_ context.Context, req MessageRequest) (map[string]interface{}, bool) {
		n.triggerWakeHook("task", req.Requester)
		return map[string]interface{}{
			"type":    MessageTypeTask,
			"message": "Task processed successfully",
		}, true
	})

	_ = n.RegisterHandler(MessageTypePeerExchange, func(_ context.Context, req MessageRequest) (map[string]interface{}, bool) {
		limit := extractPositiveInt(req.Message.Payload, "limit", 64, 256)
		peerHints := n.buildPeerHints(limit)
		return map[string]interface{}{
			"type":  MessageTypePeerExchange,
			"count": len(peerHints),
			"peers": peerHints,
		}, true
	})
}
