package agent

import (
	"fmt"
	"time"

	"fiatjaf.com/nostr"
)

func (n *AgentNode) persistInboxEvent(relayURL string, evt nostr.Event) {
	entry := InboxEvent{
		EventID:    evt.ID.Hex(),
		RelayURL:   relayURL,
		Kind:       int(evt.Kind),
		Sender:     evt.PubKey.Hex(),
		CreatedAt:  int64(evt.CreatedAt),
		ReceivedAt: time.Now().UnixMilli(),
		Content:    evt.Content,
		TagsJSON:   mustJSON(evt.Tags),
	}
	if err := n.Memory.SaveInboxEvent(entry); err != nil {
		fmt.Printf("[Inbox] Save failed for %s: %v\n", evt.ID.Hex(), err)
	}
}

func (n *AgentNode) updateRelayCursor(relayURL string, evt nostr.Event) {
	if err := n.Memory.SaveRelayCursor(relayURL, int64(evt.CreatedAt), evt.ID.Hex()); err != nil {
		fmt.Printf("[Backfill] Cursor save failed for %s: %v\n", relayURL, err)
	}
}
