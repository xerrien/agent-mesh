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
	"fiatjaf.com/nostr/nip44"
)

const (
	KindCapability      nostr.Kind = 30201
	KindKnowledgeQuery  nostr.Kind = 9002
	KindTaskRequest     nostr.Kind = 9003
	KindTaskResponse    nostr.Kind = 9004
	identityKeyFileName            = "nostr.key"
	meshTagName                    = "t"
	meshTagValue                   = "agentmesh"
	directMsgEncodingNIP44         = "nip44"
	capabilityAdvertiseInterval    = 10 * time.Second
	defaultAdvertiseTTL            = 2 * time.Minute
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
	capAdvertisers    map[string]context.CancelFunc
	peerCapabilities  map[string]AgentCapability
	localCapabilities map[string]AgentCapability
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
		capAdvertisers: make(map[string]context.CancelFunc),
		peerCapabilities: make(map[string]AgentCapability),
		localCapabilities: make(map[string]AgentCapability),
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
	n.mu.Lock()
	for name, stop := range n.capAdvertisers {
		stop()
		delete(n.capAdvertisers, name)
	}
	n.mu.Unlock()
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

func (n *AgentNode) ConnectPeer(ctx context.Context, target string) error {
	return n.PingPeer(ctx, target)
}

func (n *AgentNode) AdvertiseCapability(capability AgentCapability) {
	n.AdvertiseCapabilityFor(capability, "", defaultAdvertiseTTL)
}

func (n *AgentNode) AdvertiseCapabilityWithEth(capability AgentCapability, ethAddress string) {
	n.AdvertiseCapabilityFor(capability, ethAddress, defaultAdvertiseTTL)
}

func (n *AgentNode) PublishCapability(capability AgentCapability) error {
	return n.publishCapability(capability, "")
}

func (n *AgentNode) AdvertiseCapabilityFor(capability AgentCapability, ethAddress string, ttl time.Duration) {
	name := strings.TrimSpace(capability.Name)
	if name == "" {
		return
	}
	capability.Name = name
	if ttl <= 0 {
		ttl = defaultAdvertiseTTL
	}

	n.mu.Lock()
	if stop, ok := n.capAdvertisers[name]; ok {
		stop()
		delete(n.capAdvertisers, name)
	}
	advCtx, stop := context.WithTimeout(n.ctx, ttl)
	n.capAdvertisers[name] = stop
	n.mu.Unlock()

	go func() {
		ticker := time.NewTicker(capabilityAdvertiseInterval)
		defer ticker.Stop()
		defer func() {
			n.mu.Lock()
			delete(n.capAdvertisers, name)
			n.mu.Unlock()
		}()

		publish := func() {
			_ = n.publishCapability(capability, ethAddress)
		}

		publish()
		for {
			select {
			case <-advCtx.Done():
				return
			case <-ticker.C:
				publish()
			}
		}
	}()
}

func (n *AgentNode) StopAdvertising(capabilityName string) bool {
	name := strings.TrimSpace(capabilityName)
	if name == "" {
		return false
	}
	n.mu.Lock()
	stop, ok := n.capAdvertisers[name]
	if ok {
		stop()
		delete(n.capAdvertisers, name)
	}
	n.mu.Unlock()
	return ok
}

func (n *AgentNode) publishCapability(capability AgentCapability, ethAddress string) error {
	name := strings.TrimSpace(capability.Name)
	if name == "" {
		return fmt.Errorf("capability name cannot be empty")
	}
	capability.Name = name
	payload := map[string]interface{}{
		"capability": capability,
		"ethAddress": ethAddress,
		"timestamp":  time.Now().UnixMilli(),
	}
	tags := nostr.Tags{
		nostr.Tag{"d", capability.Name},
	}
	err := n.publishJSONEvent(KindCapability, tags, payload)
	if err == nil {
		n.mu.Lock()
		n.localCapabilities[name] = capability
		n.mu.Unlock()
	}
	return err
}

func (n *AgentNode) PublishKnowledgeQuery(query KnowledgeDiscoveryMsg) error {
	return n.publishJSONEvent(KindKnowledgeQuery, nil, query)
}

func (n *AgentNode) SendTask(ctx context.Context, target string, payload interface{}) (interface{}, error) {
	msg := AgentMessage{
		Type:      "task",
		Payload:   payload,
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	return n.sendRequest(ctx, target, msg)
}

func (n *AgentNode) PingPeer(ctx context.Context, target string) error {
	msg := AgentMessage{
		Type:      "ping",
		Payload:   map[string]interface{}{"probe": "connect"},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	if _, err := n.sendRequest(ctx, target, msg); err != nil {
		legacy := AgentMessage{
			Type:      "task",
			Payload:   map[string]interface{}{"probe": "connect"},
			Sender:    n.NodeID(),
			Timestamp: time.Now().UnixMilli(),
		}
		if _, legacyErr := n.sendRequest(ctx, target, legacy); legacyErr != nil {
			return fmt.Errorf("peer did not acknowledge ping or legacy task probe: %w", err)
		}
	}
	peerID, err := normalizePubKey(target)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.knownPeers[peerID] = struct{}{}
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) SendMessage(ctx context.Context, target string, text string) (interface{}, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, fmt.Errorf("message cannot be empty")
	}
	peerID, err := normalizePubKey(target)
	if err != nil {
		return nil, err
	}
	ciphertext, err := n.encryptForPeer(peerID, text)
	if err != nil {
		return nil, err
	}
	msg := AgentMessage{
		Type:      "message",
		Payload:   map[string]interface{}{"encoding": directMsgEncodingNIP44, "ciphertext": ciphertext},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	return n.sendRequest(ctx, peerID, msg)
}

func (n *AgentNode) QueryPeerForTaskProviders(ctx context.Context, target string, task string) ([]string, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return nil, fmt.Errorf("task cannot be empty")
	}
	msg := AgentMessage{
		Type:      "provider_lookup",
		Payload:   map[string]interface{}{"task": task},
		Sender:    n.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	resp, err := n.sendRequest(ctx, target, msg)
	if err != nil {
		return nil, err
	}
	return extractProviderList(resp), nil
}

func (n *AgentNode) QueryKnownPeersForTaskProviders(ctx context.Context, task string) ([]string, error) {
	task = strings.TrimSpace(task)
	if task == "" {
		return nil, fmt.Errorf("task cannot be empty")
	}
	peers := n.ConnectedPeers()
	unique := make(map[string]struct{})
	for _, peer := range peers {
		providers, err := n.QueryPeerForTaskProviders(ctx, peer, task)
		if err != nil {
			continue
		}
		for _, p := range providers {
			unique[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for p := range unique {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (n *AgentNode) subscribeRelay(relay *nostr.Relay) {
	filter := nostr.Filter{
		Kinds: []nostr.Kind{KindCapability, KindKnowledgeQuery, KindTaskRequest, KindTaskResponse},
		Tags:  nostr.TagMap{meshTagName: []string{meshTagValue}},
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
	n.peerCapabilities[peerID] = data.Capability
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

	n.mu.Lock()
	n.knownPeers[requester] = struct{}{}
	n.mu.Unlock()

	respPayload := map[string]interface{}{
		"status": "success",
		"agent":  n.NodeID(),
	}
	switch msg.Type {
	case "ping":
		respPayload["type"] = "pong"
	case "message":
		respPayload["type"] = "ack"
		respPayload["message"] = "delivered"
		if text, ok := n.extractMessageTextForSender(requester, msg.Payload); ok {
			fmt.Printf("[Message] %s: %s\n", requester, text)
		}
	case "provider_lookup":
		task, ok := extractTaskLookup(msg.Payload)
		if !ok {
			return
		}
		respPayload["type"] = "providers"
		respPayload["task"] = task
		respPayload["providers"] = n.findProvidersForTask(task)
	case "task":
		respPayload["message"] = "Task processed successfully"
	default:
		return
	}

	resp := AgentMessage{
		Type: "response",
		Payload:   respPayload,
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
	n.mu.Lock()
	n.knownPeers[evt.PubKey.Hex()] = struct{}{}
	ch := n.pendingTasks[reqTag[1]]
	n.mu.Unlock()

	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func (n *AgentNode) sendRequest(ctx context.Context, target string, msg AgentMessage) (interface{}, error) {
	peerID, err := normalizePubKey(target)
	if err != nil {
		return nil, err
	}
	reqID := nostr.Generate().Hex()

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
		nostr.Tag{"p", peerID},
		nostr.Tag{"req", reqID},
		nostr.Tag{"from", n.NodeID()},
	}
	if err := n.publishJSONEvent(KindTaskRequest, tags, msg); err != nil {
		return nil, err
	}

	select {
	case resp := <-respCh:
		n.mu.Lock()
		n.knownPeers[peerID] = struct{}{}
		n.mu.Unlock()
		return resp.Payload, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func normalizePubKey(raw string) (string, error) {
	pk, err := nostr.PubKeyFromHex(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("target must be nostr pubkey hex: %w", err)
	}
	return pk.Hex(), nil
}

func extractMessageText(payload interface{}) (string, bool) {
	switch v := payload.(type) {
	case string:
		s := strings.TrimSpace(v)
		return s, s != ""
	case map[string]interface{}:
		raw, ok := v["text"]
		if !ok {
			return "", false
		}
		txt, ok := raw.(string)
		if !ok {
			return "", false
		}
		txt = strings.TrimSpace(txt)
		return txt, txt != ""
	default:
		return "", false
	}
}

func (n *AgentNode) extractMessageTextForSender(sender string, payload interface{}) (string, bool) {
	if text, ok := extractMessageText(payload); ok {
		return text, true
	}
	ciphertext, ok := extractEncryptedMessagePayload(payload)
	if !ok {
		return "", false
	}
	plaintext, err := n.decryptFromPeer(sender, ciphertext)
	if err != nil {
		return "", false
	}
	plaintext = strings.TrimSpace(plaintext)
	return plaintext, plaintext != ""
}

func extractEncryptedMessagePayload(payload interface{}) (string, bool) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return "", false
	}
	rawEncoding, ok := m["encoding"]
	if !ok {
		return "", false
	}
	encoding, ok := rawEncoding.(string)
	if !ok || strings.TrimSpace(strings.ToLower(encoding)) != directMsgEncodingNIP44 {
		return "", false
	}
	rawCipher, ok := m["ciphertext"]
	if !ok {
		return "", false
	}
	ciphertext, ok := rawCipher.(string)
	if !ok {
		return "", false
	}
	ciphertext = strings.TrimSpace(ciphertext)
	return ciphertext, ciphertext != ""
}

func (n *AgentNode) encryptForPeer(peerID string, plaintext string) (string, error) {
	pk, err := nostr.PubKeyFromHex(peerID)
	if err != nil {
		return "", err
	}
	n.mu.RLock()
	sk := n.secretKey
	n.mu.RUnlock()
	ck, err := nip44.GenerateConversationKey(pk, sk)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, ck)
}

func (n *AgentNode) decryptFromPeer(peerID string, ciphertext string) (string, error) {
	pk, err := nostr.PubKeyFromHex(peerID)
	if err != nil {
		return "", err
	}
	n.mu.RLock()
	sk := n.secretKey
	n.mu.RUnlock()
	ck, err := nip44.GenerateConversationKey(pk, sk)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ciphertext, ck)
}

func extractTaskLookup(payload interface{}) (string, bool) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return "", false
	}
	raw, ok := m["task"]
	if !ok {
		return "", false
	}
	task, ok := raw.(string)
	if !ok {
		return "", false
	}
	task = strings.TrimSpace(task)
	return task, task != ""
}

func extractProviderList(payload interface{}) []string {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := m["providers"]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{})
	for _, it := range items {
		s, ok := it.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, exists := seen[s]; exists {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (n *AgentNode) findProvidersForTask(task string) []string {
	task = strings.ToLower(strings.TrimSpace(task))
	if task == "" {
		return nil
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for peerID, cap := range n.peerCapabilities {
		if capabilityMatchesTask(cap, task) {
			seen[peerID] = struct{}{}
			out = append(out, peerID)
		}
	}
	for _, cap := range n.localCapabilities {
		if capabilityMatchesTask(cap, task) {
			if _, ok := seen[n.nodeID]; !ok {
				out = append(out, n.nodeID)
				seen[n.nodeID] = struct{}{}
			}
		}
	}
	sort.Strings(out)
	return out
}

func capabilityMatchesTask(cap AgentCapability, task string) bool {
	name := strings.ToLower(strings.TrimSpace(cap.Name))
	desc := strings.ToLower(strings.TrimSpace(cap.Description))
	if strings.Contains(name, task) || strings.Contains(desc, task) {
		return true
	}
	for _, token := range strings.Fields(task) {
		if token == "" {
			continue
		}
		if strings.Contains(name, token) || strings.Contains(desc, token) {
			return true
		}
	}
	return false
}

func ensureMeshTag(tags nostr.Tags) nostr.Tags {
	for _, t := range tags {
		if len(t) >= 2 && t[0] == meshTagName && t[1] == meshTagValue {
			return tags
		}
	}
	return append(tags, nostr.Tag{meshTagName, meshTagValue})
}

func (n *AgentNode) publishJSONEvent(kind nostr.Kind, tags nostr.Tags, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tags = ensureMeshTag(tags)
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
