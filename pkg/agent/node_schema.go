package agent

import (
	"fmt"
	"strings"
)

func schemaForMessageType(msgType string) (string, bool) {
	switch strings.TrimSpace(strings.ToLower(msgType)) {
	case MessageTypePing:
		return SchemaPingV1, true
	case MessageTypeMessage:
		return SchemaMessageV1, true
	default:
		return "", false
	}
}

func validateMessageSchema(msg AgentMessage) error {
	expected, ok := schemaForMessageType(msg.Type)
	if !ok {
		return fmt.Errorf("unsupported message type: %s", msg.Type)
	}
	if msg.Meta == nil {
		return fmt.Errorf("missing message metadata")
	}
	schema := strings.TrimSpace(strings.ToLower(msg.Meta.Schema))
	if schema == "" {
		return fmt.Errorf("missing message schema")
	}
	if schema != expected {
		return fmt.Errorf("schema mismatch: expected %s got %s", expected, schema)
	}
	return nil
}

func validateMessagePayload(msg AgentMessage) error {
	switch strings.TrimSpace(strings.ToLower(msg.Type)) {
	case MessageTypePing:
		m, ok := msg.Payload.(map[string]interface{})
		if !ok {
			return fmt.Errorf("ping payload must be JSON object")
		}
		probe, ok := m["probe"].(string)
		if !ok || strings.TrimSpace(probe) == "" {
			return fmt.Errorf("ping payload requires non-empty probe")
		}
		return nil
	case MessageTypeMessage:
		m, ok := msg.Payload.(map[string]interface{})
		if !ok {
			return fmt.Errorf("message payload must be JSON object")
		}
		if _, hasText := m["text"]; hasText {
			return fmt.Errorf("message payload must not include plaintext text")
		}
		if _, ok := extractEncryptedMessagePayload(m); !ok {
			return fmt.Errorf("message payload must include encrypted ciphertext")
		}
		return nil
	default:
		return fmt.Errorf("unsupported message type: %s", msg.Type)
	}
}
