package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
)

const (
	KindCapability              nostr.Kind = 30201
	KindTaskRequest             nostr.Kind = 9003
	KindTaskResponse            nostr.Kind = 9004
	identityKeyFileName                    = "nostr.key"
	meshTagName                            = "t"
	meshTagValue                           = "agentmesh"
	directMsgEncodingNIP44                 = "nip44"
	capabilityAdvertiseInterval            = 10 * time.Second
	defaultAdvertiseTTL                    = 2 * time.Minute
	maxSeenEventsCache                     = 50000
	relayPublishTimeout                    = 8 * time.Second
	networkHealthLogInterval               = 30 * time.Second
	defaultPingTimeout                     = 20 * time.Second
	defaultSendTimeout                     = 30 * time.Second
	defaultMessageTimeoutMs     int64      = 30000
	defaultPingTimeoutMs        int64      = 20000
)

type CapabilityCallback func(peerID string, capability AgentCapability)
type MessageHandler func(ctx context.Context, req MessageRequest) (map[string]interface{}, bool)

type MessageRequest struct {
	Requester string
	Message   AgentMessage
	Event     nostr.Event
}

// ReputationChecker is a function that verifies an agent's reputation.
// Returns true if the agent is reputable, false otherwise.
type ReputationChecker func(peerID string, ethAddress string) (bool, error)

type AgentNode struct {
	Memory    *MemoryStore
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
	relays            []relayClient
	relayConnect      func(ctx context.Context, url string) (relayClient, error)
	seenEvents        map[nostr.ID]struct{}
	seenEventOrder    []nostr.ID
	knownPeers        map[string]struct{}
	peerRelays        map[string][]string
	blockedPeers      map[string]struct{}
	pendingTasks      map[string]chan AgentMessage
	capAdvertisers    map[string]context.CancelFunc
	peerCapabilities  map[string]AgentCapability
	localCapabilities map[string]AgentCapability
	mcp               *MCPAdapter
	mcpToolACL        map[string]map[string]struct{}
	mcpACLDefaultDeny bool
	mcpToolRateLimits map[string]mcpRateLimitPolicy
	mcpRateBuckets    map[string]mcpRateBucket
	mcpExecCache      map[string]mcpExecutionCache
	mcpCacheLastGC    time.Time
	mcpDefaultRate    mcpRateLimitPolicy
	messageHandlers   map[string]MessageHandler
	wakeHookCommand   string
	wakeHookCooldown  time.Duration
	wakeHookTimeout   time.Duration
	lastWakeHook      time.Time
}

func NewAgentNode(dbPath string, workspacePath string) (*AgentNode, error) {
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewMemoryStore(dbPath, workspacePath)
	if err != nil {
		cancel()
		return nil, err
	}
	wakeCmd, wakeCooldown, wakeTimeout := loadWakeHookConfig()

	node := &AgentNode{
		Memory:            store,
		workspace:         workspacePath,
		ctx:               ctx,
		cancel:            cancel,
		seenEvents:        make(map[nostr.ID]struct{}),
		seenEventOrder:    make([]nostr.ID, 0, 1024),
		knownPeers:        make(map[string]struct{}),
		peerRelays:        make(map[string][]string),
		blockedPeers:      make(map[string]struct{}),
		pendingTasks:      make(map[string]chan AgentMessage),
		capAdvertisers:    make(map[string]context.CancelFunc),
		peerCapabilities:  make(map[string]AgentCapability),
		localCapabilities: make(map[string]AgentCapability),
		mcpToolACL:        make(map[string]map[string]struct{}),
		mcpToolRateLimits: make(map[string]mcpRateLimitPolicy),
		mcpRateBuckets:    make(map[string]mcpRateBucket),
		mcpExecCache:      make(map[string]mcpExecutionCache),
		mcpDefaultRate: mcpRateLimitPolicy{
			Limit:  30,
			Window: time.Minute,
		},
		messageHandlers:  make(map[string]MessageHandler),
		wakeHookCommand:  wakeCmd,
		wakeHookCooldown: wakeCooldown,
		wakeHookTimeout:  wakeTimeout,
	}
	node.relayConnect = func(ctx context.Context, url string) (relayClient, error) {
		relay, err := nostr.RelayConnect(ctx, url, nostr.RelayOptions{})
		if err != nil {
			return nil, err
		}
		return &nostrRelayClient{relay: relay}, nil
	}
	node.initMCP()
	node.registerDefaultHandlers()
	if err := node.loadBlockedPeersFromStore(); err != nil {
		fmt.Printf("[Blocklist] Load warning: %v\n", err)
	}
	if err := node.loadMCPPolicyFromStore(); err != nil {
		fmt.Printf("[MCP] Policy load warning: %v\n", err)
	}
	return node, nil
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

func (n *AgentNode) RegisterHandler(messageType string, handler MessageHandler) error {
	messageType = strings.TrimSpace(strings.ToLower(messageType))
	if messageType == "" {
		return fmt.Errorf("message type cannot be empty")
	}
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}
	n.mu.Lock()
	n.messageHandlers[messageType] = handler
	n.mu.Unlock()
	return nil
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

func (n *AgentNode) BlockPeer(target string) error {
	peerID, err := normalizePubKey(target)
	if err != nil {
		return err
	}
	if n.Memory != nil {
		if err := n.Memory.SaveBlockedPeer(peerID); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.blockedPeers[peerID] = struct{}{}
	delete(n.knownPeers, peerID)
	delete(n.peerCapabilities, peerID)
	delete(n.peerRelays, peerID)
	n.mu.Unlock()
	return nil
}

func (n *AgentNode) UnblockPeer(target string) bool {
	peerID, err := normalizePubKey(target)
	if err != nil {
		return false
	}
	if n.Memory != nil {
		_ = n.Memory.DeleteBlockedPeer(peerID)
	}
	n.mu.Lock()
	_, existed := n.blockedPeers[peerID]
	delete(n.blockedPeers, peerID)
	n.mu.Unlock()
	return existed
}

func (n *AgentNode) BlockedPeers() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.blockedPeers))
	for p := range n.blockedPeers {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (n *AgentNode) IsBlockedPeer(peerID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	_, blocked := n.blockedPeers[peerID]
	return blocked
}

func (n *AgentNode) loadBlockedPeersFromStore() error {
	if n.Memory == nil {
		return nil
	}
	peers, err := n.Memory.ListBlockedPeers()
	if err != nil {
		return err
	}
	n.mu.Lock()
	for _, p := range peers {
		pk := strings.TrimSpace(strings.ToLower(p))
		if pk == "" {
			continue
		}
		n.blockedPeers[pk] = struct{}{}
	}
	n.mu.Unlock()
	return nil
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
		relay, err := n.relayConnect(n.ctx, url)
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
	if n.wakeHookCommand != "" {
		fmt.Printf("[WakeHook] Enabled (cooldown=%s timeout=%s)\n", n.wakeHookCooldown, n.wakeHookTimeout)
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
	relays := append([]relayClient(nil), n.relays...)
	n.mu.RUnlock()
	for _, r := range relays {
		r.Close()
	}
	if n.Memory != nil {
		return n.Memory.Close()
	}
	return nil
}

func (n *AgentNode) Relays() []relayClient {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]relayClient, len(n.relays))
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
	if capability.MCP == nil && n.mcp != nil {
		capability.MCP = n.mcp.Descriptor()
	}
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

func (n *AgentNode) seen(id nostr.ID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seenEvents[id]; ok {
		return true
	}
	n.seenEvents[id] = struct{}{}
	n.seenEventOrder = append(n.seenEventOrder, id)
	for len(n.seenEventOrder) > maxSeenEventsCache {
		oldest := n.seenEventOrder[0]
		n.seenEventOrder = n.seenEventOrder[1:]
		delete(n.seenEvents, oldest)
	}
	return false
}
