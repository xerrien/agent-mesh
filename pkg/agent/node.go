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
	relays            []*nostr.Relay
	seenEvents        map[nostr.ID]struct{}
	knownPeers        map[string]struct{}
	peerRelays        map[string][]string
	pendingTasks      map[string]chan AgentMessage
	capAdvertisers    map[string]context.CancelFunc
	peerCapabilities  map[string]AgentCapability
	localCapabilities map[string]AgentCapability
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
		Memory:       store,
		workspace:    workspacePath,
		ctx:          ctx,
		cancel:       cancel,
		seenEvents:   make(map[nostr.ID]struct{}),
		knownPeers:   make(map[string]struct{}),
		peerRelays:   make(map[string][]string),
		pendingTasks: make(map[string]chan AgentMessage),
		capAdvertisers:   make(map[string]context.CancelFunc),
		peerCapabilities: make(map[string]AgentCapability),
		localCapabilities: make(map[string]AgentCapability),
		messageHandlers:  make(map[string]MessageHandler),
		wakeHookCommand:  wakeCmd,
		wakeHookCooldown: wakeCooldown,
		wakeHookTimeout:  wakeTimeout,
	}
	node.registerDefaultHandlers()
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

func (n *AgentNode) seen(id nostr.ID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.seenEvents[id]; ok {
		return true
	}
	n.seenEvents[id] = struct{}{}
	return false
}
