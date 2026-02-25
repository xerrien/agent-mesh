package agent

import (
	"strings"
	"time"
)

func extractReceipt(payload interface{}) (string, *MessageReceipt) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return "", nil
	}
	raw, ok := m["receipt"]
	if !ok {
		return "", nil
	}
	receiptMap, ok := raw.(map[string]interface{})
	if !ok {
		return "", nil
	}
	r := &MessageReceipt{}
	if v, ok := receiptMap["stage"].(string); ok {
		r.Stage = strings.TrimSpace(strings.ToLower(v))
	}
	if v, ok := receiptMap["code"].(string); ok {
		r.Code = strings.TrimSpace(v)
	}
	if v, ok := receiptMap["detail"].(string); ok {
		r.Detail = strings.TrimSpace(v)
	}
	if v, ok := receiptMap["replyTo"].(string); ok {
		r.ReplyTo = strings.TrimSpace(v)
	}
	if v, ok := receiptMap["at"].(float64); ok {
		r.At = int64(v)
	}
	return r.Stage, r
}

func unwrapResponsePayload(payload interface{}) interface{} {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return payload
	}
	if data, ok := m["data"]; ok {
		return data
	}
	return payload
}

func responsePayloadWithReceipt(stage string, replyTo string, code string, detail string, data interface{}) map[string]interface{} {
	receipt := map[string]interface{}{
		"stage":   stage,
		"at":      time.Now().UnixMilli(),
		"replyTo": replyTo,
	}
	if strings.TrimSpace(code) != "" {
		receipt["code"] = strings.TrimSpace(code)
	}
	if strings.TrimSpace(detail) != "" {
		receipt["detail"] = strings.TrimSpace(detail)
	}
	out := map[string]interface{}{
		"receipt": receipt,
	}
	if data != nil {
		out["data"] = data
	}
	return out
}
