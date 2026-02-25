package agent

import (
	"context"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

func TestNormalizeEncryptedMessagePayload(t *testing.T) {
	t.Parallel()

	n := &AgentNode{secretKey: nostr.Generate()}
	peer := nostr.Generate().Public().Hex()

	out, err := n.normalizeEncryptedMessagePayload(peer, map[string]interface{}{"text": "hello"})
	if err != nil {
		t.Fatalf("expected encryption to succeed, got %v", err)
	}
	if out["encoding"] != directMsgEncodingNIP44 {
		t.Fatalf("expected encoding %q, got %v", directMsgEncodingNIP44, out["encoding"])
	}
	cipher, ok := out["ciphertext"].(string)
	if !ok || strings.TrimSpace(cipher) == "" {
		t.Fatalf("expected non-empty ciphertext")
	}

	passthrough := map[string]interface{}{
		"encoding":   directMsgEncodingNIP44,
		"ciphertext": "v2:abc123",
	}
	out2, err := n.normalizeEncryptedMessagePayload(peer, passthrough)
	if err != nil {
		t.Fatalf("expected passthrough to succeed, got %v", err)
	}
	if out2["ciphertext"] != "v2:abc123" {
		t.Fatalf("expected passthrough ciphertext preserved")
	}
}

func TestNormalizeEncryptedMessagePayloadRejectsInvalid(t *testing.T) {
	t.Parallel()

	n := &AgentNode{secretKey: nostr.Generate()}
	peer := nostr.Generate().Public().Hex()

	_, err := n.normalizeEncryptedMessagePayload(peer, map[string]interface{}{"text": ""})
	if err == nil {
		t.Fatalf("expected empty text to fail")
	}

	_, err = n.normalizeEncryptedMessagePayload(peer, map[string]interface{}{"foo": "bar"})
	if err == nil {
		t.Fatalf("expected missing text/ciphertext to fail")
	}
}

func TestSendTypedRejectsUnsupportedType(t *testing.T) {
	t.Parallel()

	n := &AgentNode{}
	_, err := n.SendTyped(context.Background(), "abcd", "task", map[string]interface{}{"x": 1})
	if err == nil {
		t.Fatalf("expected unsupported type to fail")
	}
}
