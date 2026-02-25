package agent

import (
	"fmt"
	"path/filepath"
	"testing"

	"fiatjaf.com/nostr"
)

func TestSeenEventsPrunedAtBound(t *testing.T) {
	t.Parallel()

	node, err := NewAgentNode(filepath.Join(t.TempDir(), "test.db"), t.TempDir())
	if err != nil {
		t.Fatalf("new node: %v", err)
	}
	defer func() { _ = node.Stop() }()

	total := maxSeenEventsCache + 128
	var firstID nostr.ID
	for i := 0; i < total; i++ {
		id := nostr.MustIDFromHex(fmt.Sprintf("%064x", i+1))
		if i == 0 {
			firstID = id
		}
		if seenBefore := node.seen(id); seenBefore {
			t.Fatalf("id should be new at insertion %d", i)
		}
	}

	node.mu.RLock()
	size := len(node.seenEvents)
	node.mu.RUnlock()
	if size > maxSeenEventsCache {
		t.Fatalf("seenEvents cache exceeded bound: got %d max %d", size, maxSeenEventsCache)
	}

	// Oldest entry should have been evicted after exceeding bound.
	if seenBefore := node.seen(firstID); seenBefore {
		t.Fatalf("expected oldest seen ID to be evicted and treated as new")
	}
}
