package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) SendTyped(ctx context.Context, target string, msgType string, payload interface{}) (interface{}, error) {
	msgType = strings.TrimSpace(strings.ToLower(msgType))
	if msgType == "" {
		return nil, fmt.Errorf("message type cannot be empty")
	}
	schema, ok := schemaForMessageType(msgType)
	if !ok {
		return nil, fmt.Errorf("unsupported message type: %s", msgType)
	}
	switch msgType {
	case MessageTypeMessage:
		peerID, err := normalizePubKey(target)
		if err != nil {
			return nil, err
		}
		ciphertextPayload, err := n.normalizeEncryptedMessagePayload(peerID, payload)
		if err != nil {
			return nil, err
		}
		payload = ciphertextPayload
	}
	msg := AgentMessage{
		Type:      msgType,
		Payload:   payload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
		Meta:      defaultMessageMeta(schema, msgType, 30000),
	}
	return n.sendRequest(ctx, target, msg)
}

func (n *AgentNode) PingPeer(ctx context.Context, target string) error {
	msg := AgentMessage{
		Type:      MessageTypePing,
		Payload:   map[string]interface{}{"probe": "connect"},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
		Meta:      defaultMessageMeta(SchemaPingV1, "connectivity_probe", 20000),
	}
	if _, err := n.sendRequest(ctx, target, msg); err != nil {
		return fmt.Errorf("peer did not acknowledge ping: %w", err)
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
	if n.IsBlockedPeer(peerID) {
		return nil, fmt.Errorf("peer is blocked: %s", peerID)
	}
	reqID := nostr.Generate().Hex()

	respCh := make(chan AgentMessage, 4)
	n.mu.Lock()
	n.pendingTasks[reqID] = respCh
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pendingTasks, reqID)
		n.mu.Unlock()
	}()

	if msg.Meta == nil {
		msg.Meta = &MessageMeta{}
	}
	if strings.TrimSpace(msg.Meta.ID) == "" {
		msg.Meta.ID = reqID
	}
	if msg.Meta.RequiresAck == false {
		msg.Meta.RequiresAck = true
	}
	if err := validateMessageSchema(msg); err != nil {
		return nil, err
	}
	if err := validateMessagePayload(msg); err != nil {
		return nil, err
	}

	tags := nostr.Tags{
		nostr.Tag{"p", peerID},
		nostr.Tag{"req", reqID},
		nostr.Tag{"from", n.NodeID()},
	}
	if err := n.publishJSONEventForPeer(KindTaskRequest, tags, msg, peerID); err != nil {
		return nil, err
	}

	for {
		select {
		case resp := <-respCh:
			n.mu.Lock()
			n.knownPeers[peerID] = struct{}{}
			n.mu.Unlock()
			stage, receipt := extractReceipt(resp.Payload)
			switch stage {
			case ReceiptStageAccepted:
				continue
			case ReceiptStageFailed:
				if receipt != nil && receipt.Detail != "" {
					return nil, fmt.Errorf("request failed: %s", receipt.Detail)
				}
				if receipt != nil && receipt.Code != "" {
					return nil, fmt.Errorf("request failed: %s", receipt.Code)
				}
				return nil, fmt.Errorf("request failed")
			case ReceiptStageProcessed:
				return unwrapResponsePayload(resp.Payload), nil
			default:
				return nil, fmt.Errorf("invalid response: missing receipt stage")
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (n *AgentNode) dispatchMessageHandler(ctx context.Context, req MessageRequest) (map[string]interface{}, bool) {
	msgType := strings.TrimSpace(strings.ToLower(req.Message.Type))
	if msgType == "" {
		return nil, false
	}
	if err := validateMessageSchema(req.Message); err != nil {
		return map[string]interface{}{"error": err.Error()}, false
	}
	if err := validateMessagePayload(req.Message); err != nil {
		return map[string]interface{}{"error": err.Error()}, false
	}
	n.mu.RLock()
	handler := n.messageHandlers[msgType]
	n.mu.RUnlock()
	if handler == nil {
		return nil, false
	}
	resp, ok := handler(ctx, req)
	if !ok {
		return resp, false
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

	_ = n.RegisterHandler(MessageTypeMessage, func(ctx context.Context, req MessageRequest) (map[string]interface{}, bool) {
		if text, ok := n.extractMessageTextForSender(req.Requester, req.Message.Payload); ok {
			fmt.Printf("[Message] %s: %s\n", req.Requester, text)
			tool, args, invoke, parseErr := parseMCPInvocation(text)
			if parseErr != nil {
				return map[string]interface{}{"error": parseErr.Error()}, false
			}
			if invoke {
				if args == nil {
					args = map[string]interface{}{}
				}
				if _, exists := args["sender"]; !exists {
					args["sender"] = req.Requester
				}
				reqID := mcpRequestID(req)
				result, deduped, err := n.executeMCPToolForRequest(ctx, req.Requester, reqID, tool, args)
				if err != nil {
					return map[string]interface{}{"error": err.Error()}, false
				}
				n.triggerWakeHook("message", req.Requester)
				return map[string]interface{}{
					"type":      "mcp_result",
					"tool":      tool,
					"requestId": reqID,
					"deduped":   deduped,
					"result":    result,
				}, true
			}
		}
		n.triggerWakeHook("message", req.Requester)
		return map[string]interface{}{
			"type":    "ack",
			"message": "delivered",
		}, true
	})
}

func defaultMessageMeta(schema string, purpose string, timeoutMs int64) *MessageMeta {
	return &MessageMeta{
		Schema:      schema,
		Purpose:     purpose,
		TimeoutMs:   timeoutMs,
		RequiresAck: true,
	}
}
