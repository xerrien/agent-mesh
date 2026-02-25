package agent

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

type fakeRelaySub struct {
	filter nostr.Filter
	sub    *nostr.Subscription
	closed bool
}

type fakeRelay struct {
	url    string
	mu     sync.Mutex
	closed bool
	subs   []*fakeRelaySub
}

func newFakeRelay(url string) *fakeRelay {
	return &fakeRelay{url: url, subs: make([]*fakeRelaySub, 0)}
}

func (r *fakeRelay) URL() string { return r.url }

func (r *fakeRelay) Publish(_ context.Context, evt nostr.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return context.Canceled
	}
	for _, s := range r.subs {
		if !matchesFilter(s.filter, evt) {
			continue
		}
		select {
		case s.sub.Events <- evt:
		default:
		}
	}
	return nil
}

func (r *fakeRelay) Subscribe(ctx context.Context, filter nostr.Filter, _ nostr.SubscriptionOptions) (*nostr.Subscription, error) {
	sub := &nostr.Subscription{
		Filter: filter,
		Events: make(chan nostr.Event, 64),
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		close(sub.Events)
		return sub, nil
	}
	r.subs = append(r.subs, &fakeRelaySub{filter: filter, sub: sub})
	r.mu.Unlock()

	go func() {
		<-ctx.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		for i, s := range r.subs {
			if s.sub == sub {
				if !s.closed {
					close(s.sub.Events)
					s.closed = true
				}
				r.subs = append(r.subs[:i], r.subs[i+1:]...)
				break
			}
		}
	}()
	return sub, nil
}

func (r *fakeRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for _, s := range r.subs {
		if !s.closed {
			close(s.sub.Events)
			s.closed = true
		}
	}
	r.subs = nil
}

func matchesFilter(f nostr.Filter, evt nostr.Event) bool {
	if len(f.Kinds) > 0 {
		ok := false
		for _, k := range f.Kinds {
			if k == evt.Kind {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.Since > 0 && evt.CreatedAt < f.Since {
		return false
	}
	for tagName, vals := range f.Tags {
		if len(vals) == 0 {
			continue
		}
		found := false
		for _, tag := range evt.Tags {
			if len(tag) < 2 || tag[0] != tagName {
				continue
			}
			for _, want := range vals {
				if tag[1] == want {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestNetworkPingOverFakeRelay(t *testing.T) {
	t.Parallel()

	relay := newFakeRelay("wss://fake-relay.test")
	dir := t.TempDir()

	nodeA, err := NewAgentNode(filepath.Join(dir, "a.db"), filepath.Join(dir, "a"))
	if err != nil {
		t.Fatalf("new nodeA: %v", err)
	}
	defer func() { _ = nodeA.Stop() }()
	nodeB, err := NewAgentNode(filepath.Join(dir, "b.db"), filepath.Join(dir, "b"))
	if err != nil {
		t.Fatalf("new nodeB: %v", err)
	}
	defer func() { _ = nodeB.Stop() }()

	skA := nostr.Generate()
	skB := nostr.Generate()
	nodeA.mu.Lock()
	nodeA.secretKey = skA
	nodeA.nodeID = skA.Public().Hex()
	nodeA.relays = []relayClient{relay}
	nodeA.relayURLs = []string{relay.URL()}
	nodeA.mu.Unlock()
	nodeB.mu.Lock()
	nodeB.secretKey = skB
	nodeB.nodeID = skB.Public().Hex()
	nodeB.relays = []relayClient{relay}
	nodeB.relayURLs = []string{relay.URL()}
	nodeB.mu.Unlock()

	go nodeA.subscribeRelay(relay)
	go nodeB.subscribeRelay(relay)
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := nodeA.PingPeer(ctx, nodeB.NodeID()); err != nil {
		t.Fatalf("ping failed over fake relay: %v", err)
	}
	if !contains(nodeA.ConnectedPeers(), nodeB.NodeID()) {
		t.Fatalf("expected nodeA to know nodeB after ping")
	}
}

func contains(items []string, want string) bool {
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}
