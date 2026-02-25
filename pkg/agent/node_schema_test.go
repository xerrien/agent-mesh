package agent

import "testing"

func TestSchemaForMessageType(t *testing.T) {
	t.Parallel()

	if got, ok := schemaForMessageType("ping"); !ok || got != SchemaPingV1 {
		t.Fatalf("expected ping schema %q, got %q ok=%v", SchemaPingV1, got, ok)
	}
	if got, ok := schemaForMessageType("message"); !ok || got != SchemaMessageV1 {
		t.Fatalf("expected message schema %q, got %q ok=%v", SchemaMessageV1, got, ok)
	}
	if _, ok := schemaForMessageType("task"); ok {
		t.Fatalf("did not expect task to be supported")
	}
}

func TestValidateMessageSchema(t *testing.T) {
	t.Parallel()

	okMsg := AgentMessage{
		Type: MessageTypePing,
		Meta: &MessageMeta{Schema: SchemaPingV1},
	}
	if err := validateMessageSchema(okMsg); err != nil {
		t.Fatalf("expected valid schema, got error: %v", err)
	}

	missingMeta := AgentMessage{Type: MessageTypePing}
	if err := validateMessageSchema(missingMeta); err == nil {
		t.Fatalf("expected error for missing meta")
	}

	mismatch := AgentMessage{
		Type: MessageTypePing,
		Meta: &MessageMeta{Schema: SchemaMessageV1},
	}
	if err := validateMessageSchema(mismatch); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestValidateMessagePayload(t *testing.T) {
	t.Parallel()

	ping := AgentMessage{
		Type:    MessageTypePing,
		Payload: map[string]interface{}{"probe": "connect"},
	}
	if err := validateMessagePayload(ping); err != nil {
		t.Fatalf("expected valid ping payload, got %v", err)
	}

	badPing := AgentMessage{
		Type:    MessageTypePing,
		Payload: map[string]interface{}{"probe": ""},
	}
	if err := validateMessagePayload(badPing); err == nil {
		t.Fatalf("expected invalid ping payload")
	}

	message := AgentMessage{
		Type: MessageTypeMessage,
		Payload: map[string]interface{}{
			"encoding":   directMsgEncodingNIP44,
			"ciphertext": "v2:placeholder",
		},
	}
	if err := validateMessagePayload(message); err != nil {
		t.Fatalf("expected valid message payload, got %v", err)
	}

	badMessage := AgentMessage{
		Type:    MessageTypeMessage,
		Payload: map[string]interface{}{"text": "plain"},
	}
	if err := validateMessagePayload(badMessage); err == nil {
		t.Fatalf("expected invalid unencrypted message payload")
	}

	ambiguousMessage := AgentMessage{
		Type: MessageTypeMessage,
		Payload: map[string]interface{}{
			"text":       "plain",
			"encoding":   directMsgEncodingNIP44,
			"ciphertext": "v2:placeholder",
		},
	}
	if err := validateMessagePayload(ambiguousMessage); err == nil {
		t.Fatalf("expected ambiguous message payload with text+ciphertext to fail")
	}
}
