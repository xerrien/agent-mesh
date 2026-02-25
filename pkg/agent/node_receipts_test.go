package agent

import "testing"

func TestReceiptHelpers(t *testing.T) {
	t.Parallel()

	payload := responsePayloadWithReceipt(
		ReceiptStageProcessed,
		"req-1",
		"",
		"done",
		map[string]interface{}{"ok": true},
	)

	stage, receipt := extractReceipt(payload)
	if stage != ReceiptStageProcessed {
		t.Fatalf("expected stage %q, got %q", ReceiptStageProcessed, stage)
	}
	if receipt == nil {
		t.Fatalf("expected receipt object")
	}
	if receipt.ReplyTo != "req-1" {
		t.Fatalf("expected replyTo req-1, got %q", receipt.ReplyTo)
	}

	data := unwrapResponsePayload(payload)
	m, ok := data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map payload")
	}
	if v, ok := m["ok"].(bool); !ok || !v {
		t.Fatalf("expected ok=true in response data")
	}
}
