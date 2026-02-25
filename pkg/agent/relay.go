package agent

import (
	"context"

	"fiatjaf.com/nostr"
)

type relayClient interface {
	URL() string
	Publish(ctx context.Context, evt nostr.Event) error
	Subscribe(ctx context.Context, filter nostr.Filter, opts nostr.SubscriptionOptions) (*nostr.Subscription, error)
	Close()
}

type nostrRelayClient struct {
	relay *nostr.Relay
}

func (r *nostrRelayClient) URL() string {
	if r == nil || r.relay == nil {
		return ""
	}
	return r.relay.URL
}

func (r *nostrRelayClient) Publish(ctx context.Context, evt nostr.Event) error {
	return r.relay.Publish(ctx, evt)
}

func (r *nostrRelayClient) Subscribe(ctx context.Context, filter nostr.Filter, opts nostr.SubscriptionOptions) (*nostr.Subscription, error) {
	return r.relay.Subscribe(ctx, filter, opts)
}

func (r *nostrRelayClient) Close() {
	if r == nil || r.relay == nil {
		return
	}
	r.relay.Close()
}
