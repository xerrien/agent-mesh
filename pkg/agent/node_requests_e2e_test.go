package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
)

func TestDispatchMessageHandlerMCPEncryptedE2E(t *testing.T) {
	t.Parallel()

	db := filepath.Join(t.TempDir(), "test.db")
	node, err := NewAgentNode(db, t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	nodeSK := nostr.Generate()
	node.secretKey = nodeSK
	node.nodeID = nodeSK.Public().Hex()

	requesterSK := nostr.Generate()
	requesterPub := requesterSK.Public().Hex()

	plainInvoke := `{"tool":"local.echo","args":{"x":1}}`
	ciphertext, err := encryptForTarget(requesterSK, nodeSK.Public().Hex(), plainInvoke)
	if err != nil {
		t.Fatalf("encrypt invocation: %v", err)
	}

	msg := AgentMessage{
		Type: MessageTypeMessage,
		Payload: map[string]interface{}{
			"encoding":   directMsgEncodingNIP44,
			"ciphertext": ciphertext,
		},
		Sender:    requesterPub,
		Timestamp: 1,
		Meta: &MessageMeta{
			ID:     "req-e2e-1",
			Schema: SchemaMessageV1,
		},
	}

	req := MessageRequest{
		Requester: requesterPub,
		Message:   msg,
	}

	resp1, ok := node.dispatchMessageHandler(context.Background(), req)
	if !ok {
		t.Fatalf("expected handler to process MCP invocation")
	}
	if resp1["type"] != "mcp_result" {
		t.Fatalf("expected type=mcp_result, got %v", resp1["type"])
	}
	if resp1["tool"] != "local.echo" {
		t.Fatalf("expected tool local.echo, got %v", resp1["tool"])
	}
	if resp1["requestId"] != "req-e2e-1" {
		t.Fatalf("expected requestId=req-e2e-1, got %v", resp1["requestId"])
	}
	if deduped, _ := resp1["deduped"].(bool); deduped {
		t.Fatalf("first response should not be deduped")
	}
	data1, ok := resp1["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result map")
	}
	echo1, ok := data1["echo"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result.echo map")
	}
	if got := echo1["x"]; got != float64(1) {
		t.Fatalf("expected echo.x=1, got %v", got)
	}

	resp2, ok := node.dispatchMessageHandler(context.Background(), req)
	if !ok {
		t.Fatalf("expected replay to be handled")
	}
	if deduped, _ := resp2["deduped"].(bool); !deduped {
		t.Fatalf("second response should be deduped")
	}
	data2, ok := resp2["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected second result map")
	}

	// Ensure replay returned cached tool output (same payload bytes).
	b1, _ := json.Marshal(data1)
	b2, _ := json.Marshal(data2)
	if string(b1) != string(b2) {
		t.Fatalf("expected cached replay result to match first result")
	}
}

func encryptForTarget(senderSK nostr.SecretKey, targetPubHex string, plaintext string) (string, error) {
	targetPub, err := nostr.PubKeyFromHex(targetPubHex)
	if err != nil {
		return "", err
	}
	ck, err := nip44.GenerateConversationKey(targetPub, senderSK)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, ck)
}
