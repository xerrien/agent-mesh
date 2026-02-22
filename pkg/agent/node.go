package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
)

const (
	KindCapability      nostr.Kind = 30201
	KindKnowledgeQuery  nostr.Kind = 30202
	KindTaskRequest     nostr.Kind = 30203
	KindTaskResponse    nostr.Kind = 30204
	identityKeyFileName            = "nostr.key"
)

type CapabilityCallback func(peerID string, capability AgentCapability)

// ReputationChecker is a function that verifies an agent's reputation.
// Returns true if the agent is reputable, false otherwise.
type ReputationChecker func(peerID string, ethAddress string) (bool, error)

type AgentNode struct {
	Memory    *MemoryStore
	Watcher   *EventWatcher
	ERCClient *ERC8004Client
	workspace string
	ctx       context.Context
	cancel    context.CancelFunc
	secretKey nostr.SecretKey
	nodeID    string

	mu                sync.RWMutex
	reputationChecker ReputationChecker
	onCapCallbacks    []CapabilityCallback
	relayURLs         []string
	relays            []*nostr.Relay
	seenEvents        map[nostr.ID]struct{}
	knownPeers        map[string]struct{}
	pendingTasks      map[string]chan AgentMessage
}

func NewAgentNode(dbPath string, workspacePath string) (*AgentNode, error) {
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewMemoryStore(dbPath, workspacePath)
	if err != nil {
		cancel()
		return nil, err
	}

	return &AgentNode{
		Memory:       store,
		workspace:    workspacePath,
		ctx:          ctx,
		cancel:       cancel,
		seenEvents:   make(map[nostr.ID]struct{}),
		knownPeers:   make(map[string]struct{}),
		pendingTasks: make(map[string]chan AgentMessage),
	}, nil
}

func (n *AgentNode) SetReputationChecker(checker ReputationChecker) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reputationChecker = checker
}

func (n *AgentNode) OnCapability(cb CapabilityCallback) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onCapCallbacks = append(n.onCapCallbacks, cb)
}

func (n *AgentNode) NodeID() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.nodeID
}

func (n *AgentNode) RelayURLs() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, len(n.relayURLs))
	copy(out, n.relayURLs)
	return out
}

func (n *AgentNode) ConnectedPeers() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.knownPeers))
	for p := range n.knownPeers {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (n *AgentNode) Start(_ string, bootstrapNodes string) error {
	sk, err := n.loadOrCreateKey()
	if err != nil {
		return fmt.Errorf("failed to load/create identity key: %w", err)
	}

	relayURLs := parseRelayURLs(bootstrapNodes)
	if len(relayURLs) == 0 {
		return fmt.Errorf("no nostr relays configured; pass -bootstrap as comma-separated wss:// relay URLs")
	}

	n.mu.Lock()
	n.secretKey = sk
	n.nodeID = sk.Public().Hex()
	n.relayURLs = relayURLs
	n.mu.Unlock()

	for _, url := range relayURLs {
		relay, err := nostr.RelayConnect(n.ctx, url, nostr.RelayOptions{})
		if err != nil {
			fmt.Printf("[Nostr] Relay connect failed %s: %v\n", url, err)
			continue
		}
		fmt.Printf("[Nostr] Connected relay: %s\n", url)
		n.mu.Lock()
		n.relays = append(n.relays, relay)
		n.mu.Unlock()
		go n.subscribeRelay(relay)
	}

	if len(n.Relays()) == 0 {
		return fmt.Errorf("failed to connect to any nostr relay")
	}

	go n.logNetworkHealth()
	return nil
}

func (n *AgentNode) Stop() error {
	n.cancel()
	n.mu.RLock()
	relays := append([]*nostr.Relay(nil), n.relays...)
	n.mu.RUnlock()
	for _, r := range relays {
		r.Close()
	}
	return nil
}

func (n *AgentNode) Relays() []*nostr.Relay {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]*nostr.Relay, len(n.relays))
	copy(out, n.relays)
	return out
}

func (n *AgentNode) ConnectPeer(_ context.Context, target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("empty target")
	}
	pk, err := nostr.PubKeyFromHex(target)
	if err != nil {
		return fmt.Errorf("connect expects nostr pubkey hex: %w", err)
	}
	peerID := pk.Hex()
	n.mu.Lock()
	n.knownPeers[peerID] = struct{}{}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) AdvertiseCapability(capability AgentCapability) {
	n.AdvertiseCapabilityWithEth(capability, "")
}

func (n *AgentNode) AdvertiseCapabilityWithEth(capability AgentCapability, ethAddress string) {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			payload := map[string]interface{}{
				"capability": capability,
				"ethAddress": ethAddress,
				"timestamp":  time.Now().UnixMilli(),
			}
			_ = n.publishJSONEvent(KindCapability, nil, payload)
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (n *AgentNode) PublishKnowledgeQuery(query KnowledgeDiscoveryMsg) error {
	return n.publishJSONEvent(KindKnowledgeQuery, nil, query)
}

func (n *AgentNode) SendTask(ctx context.Context, target string, payload interface{}) (interface{}, error) {
	pk, err := nostr.PubKeyFromHex(strings.TrimSpace(target))
	if err != nil {
		return nil, fmt.Errorf("target must be nostr pubkey hex: %w", err)
	}
	reqID := nostr.Generate().Hex()

	msg := AgentMessage{
		Type:      "task",
		Payload:   payload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}

	respCh := make(chan AgentMessage, 1)
	n.mu.Lock()
	n.pendingTasks[reqID] = respCh
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.pendingTasks, reqID)
		n.mu.Unlock()
	}()

	tags := nostr.Tags{
		nostr.Tag{"p", pk.Hex()},
		nostr.Tag{"req", reqID},
		nostr.Tag{"from", n.NodeID()},
	}
	if err := n.publishJSONEvent(KindTaskRequest, tags, msg); err != nil {
		return nil, err
	}

	select {
	case resp := <-respCh:
		return resp.Payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *AgentNode) subscribeRelay(relay *nostr.Relay) {
	filter := nostr.Filter{
		Kinds: []nostr.Kind{KindCapability, KindKnowledgeQuery, KindTaskRequest, KindTaskResponse},
	}
	sub, err := relay.Subscribe(n.ctx, filter, nostr.SubscriptionOptions{})
	if err != nil {
		fmt.Printf("[Nostr] Subscribe failed on %s: %v\n", relay.URL, err)
		return
	}

	for evt := range sub.Events {
		if evt.PubKey.Hex() == n.NodeID() {
			continue
		}
		if n.seen(evt.ID) {
			continue
		}
		n.handleEvent(evt)
	}
}

func (n *AgentNode) handleEvent(evt nostr.Event) {
	switch evt.Kind {
	case KindCapability:
		n.handleCapabilityEvent(evt)
	case KindKnowledgeQuery:
		n.handleKnowledgeQueryEvent(evt)
	case KindTaskRequest:
		n.handleTaskRequestEvent(evt)
	case KindTaskResponse:
		n.handleTaskResponseEvent(evt)
	}
}

func (n *AgentNode) handleCapabilityEvent(evt nostr.Event) {
	var data struct {
		Capability AgentCapability `json:"capability"`
		EthAddress string          `json:"ethAddress,omitempty"`
	}
	if err := json.Unmarshal([]byte(evt.Content), &data); err != nil {
		return
	}

	peerID := evt.PubKey.Hex()
	n.mu.Lock()
	n.knownPeers[peerID] = struct{}{}
	checker := n.reputationChecker
	callbacks := append([]CapabilityCallback(nil), n.onCapCallbacks...)
	n.mu.Unlock()

	if checker != nil && data.EthAddress != "" {
		ok, err := checker(peerID, data.EthAddress)
		if err != nil || !ok {
			return
		}
	}

	for _, cb := range callbacks {
		cb(peerID, data.Capability)
	}
}

func (n *AgentNode) handleKnowledgeQueryEvent(evt nostr.Event) {
	var query KnowledgeDiscoveryMsg
	if err := json.Unmarshal([]byte(evt.Content), &query); err != nil {
		return
	}
	fmt.Printf("[Memory] Received discovery query: %q from %s\n", query.Query, query.Requester)

	var matches []MemoryChunk
	n.Memory.mu.RLock()
	for _, tag := range query.Tags {
		items, err := n.Memory.Search(tag)
		if err == nil {
			matches = append(matches, items...)
		}
	}
	n.Memory.mu.RUnlock()
	if len(matches) > 0 {
		fmt.Printf("[Memory] Found %d potential matches for %q\n", len(matches), query.Query)
	}
}

func (n *AgentNode) handleTaskRequestEvent(evt nostr.Event) {
	targetTag := evt.Tags.Find("p")
	if targetTag == nil || len(targetTag) < 2 || targetTag[1] != n.NodeID() {
		return
	}

	var msg AgentMessage
	if err := json.Unmarshal([]byte(evt.Content), &msg); err != nil {
		return
	}
	if msg.Type != "task" {
		return
	}

	reqTag := evt.Tags.Find("req")
	if reqTag == nil || len(reqTag) < 2 {
		return
	}
	fromTag := evt.Tags.Find("from")
	if fromTag == nil || len(fromTag) < 2 {
		return
	}
	requester := fromTag[1]
	if _, err := nostr.PubKeyFromHex(requester); err != nil {
		return
	}

	resp := AgentMessage{
		Type: "response",
		Payload: map[string]interface{}{
			"status":  "success",
			"agent":   n.NodeID(),
			"message": "Task processed successfully",
		},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}

	tags := nostr.Tags{
		nostr.Tag{"p", requester},
		nostr.Tag{"req", reqTag[1]},
		nostr.Tag{"from", n.NodeID()},
	}
	_ = n.publishJSONEvent(KindTaskResponse, tags, resp)
}

func (n *AgentNode) handleTaskResponseEvent(evt nostr.Event) {
	targetTag := evt.Tags.Find("p")
	if targetTag == nil || len(targetTag) < 2 || targetTag[1] != n.NodeID() {
		return
	}
	reqTag := evt.Tags.Find("req")
	if reqTag == nil || len(reqTag) < 2 {
		return
	}

	var msg AgentMessage
	if err := json.Unmarshal([]byte(evt.Content), &msg); err != nil {
		return
	}

	n.mu.RLock()
	ch := n.pendingTasks[reqTag[1]]
	n.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func (n *AgentNode) publishJSONEvent(kind nostr.Kind, tags nostr.Tags, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	evt := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      kind,
		Tags:      tags,
		Content:   string(body),
	}
	n.mu.RLock()
	sk := n.secretKey
	relays := append([]*nostr.Relay(nil), n.relays...)
	n.mu.RUnlock()
	if err := evt.Sign(sk); err != nil {
		return err
	}
	if len(relays) == 0 {
		return fmt.Errorf("no connected relays")
	}

	var wg sync.WaitGroup
	var okCount int
	var errMu sync.Mutex
	errs := make([]string, 0, len(relays))
	for _, relay := range relays {
		wg.Add(1)
		go func(r *nostr.Relay) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
			defer cancel()
			if err := r.Publish(ctx, evt); err != nil {
				errMu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", r.URL, err))
				errMu.Unlock()
				return
			}
			errMu.Lock()
			okCount++
			errMu.Unlock()
		}(relay)
	}
	wg.Wait()

	if okCount == 0 {
		return fmt.Errorf("publish failed on all relays: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (n *AgentNode) seen(id nostr.ID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seenEvents[id]; ok {
		return true
	}
	n.seenEvents[id] = struct{}{}
	return false
}

func (n *AgentNode) loadOrCreateKey() (nostr.SecretKey, error) {
	keyPath := filepath.Join(n.workspace, identityKeyFileName)
	if b, err := os.ReadFile(keyPath); err == nil {
		hexKey := strings.TrimSpace(string(b))
		sk, err := nostr.SecretKeyFromHex(hexKey)
		if err == nil {
			fmt.Printf("[Identity] Loaded existing key from %s\n", keyPath)
			return sk, nil
		}
	}

	sk := nostr.Generate()
	if err := os.WriteFile(keyPath, []byte(sk.Hex()), 0600); err != nil {
		fmt.Printf("[Identity] Warning: could not save key to %s: %v\n", keyPath, err)
	} else {
		fmt.Printf("[Identity] Generated new key, saved to %s\n", keyPath)
	}
	return sk, nil
}

func (n *AgentNode) logNetworkHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			n.mu.RLock()
			relayCount := len(n.relays)
			peerCount := len(n.knownPeers)
			n.mu.RUnlock()
			fmt.Printf("[Network] Connected relays: %d | Known peers: %d\n", relayCount, peerCount)
		case <-n.ctx.Done():
			return
		}
	}
}

func parseRelayURLs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		u := strings.TrimSpace(p)
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "ws://") && !strings.HasPrefix(u, "wss://") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
