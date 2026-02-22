package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/multiformats/go-multiaddr"
)

const (
	DiscoveryTopic          = "agentmesh:discovery"
	KnowledgeDiscoveryTopic = "agentmesh:knowledge_discovery"
	TaskProtocol            = "/agentmesh/task/1.0.0"
	MemoryProtocol          = "/agentmesh/memory/1.0.0"
)

type CapabilityCallback func(peerID string, capability AgentCapability)

// ReputationChecker is a function that verifies an agent's reputation.
// Returns true if the agent is reputable, false otherwise.
type ReputationChecker func(peerID string, ethAddress string) (bool, error)

type AgentNode struct {
	Host              host.Host
	PubSub            *pubsub.PubSub
	DiscoveryTopic    *pubsub.Topic
	KnowledgeTopic    *pubsub.Topic
	Memory            *MemoryStore
	Watcher           *EventWatcher
	ERCClient         *ERC8004Client
	DHT               *dht.IpfsDHT
	onCapCallbacks    []CapabilityCallback
	reputationChecker ReputationChecker
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	privKey           crypto.PrivKey
	workspacePath     string // used to persist identity key
}

func NewAgentNode(dbPath string, workspacePath string) (*AgentNode, error) {
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewMemoryStore(dbPath, workspacePath)
	if err != nil {
		cancel()
		return nil, err
	}
	return &AgentNode{
		ctx:           ctx,
		cancel:        cancel,
		Memory:        store,
		workspacePath: workspacePath,
	}, nil
}

// SetReputationChecker sets a custom function that is called to verify an agent's reputation.
func (n *AgentNode) SetReputationChecker(checker ReputationChecker) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reputationChecker = checker
}

func (n *AgentNode) Start(listenAddr string, bootstrapNodes string) error {
	// --- 1. Persistent Identity ---
	// Load or generate a persistent private key so the peer ID survives restarts.
	priv, err := n.loadOrCreateKey()
	if err != nil {
		return fmt.Errorf("failed to load/create identity key: %w", err)
	}
	n.privKey = priv

	// Resource Manager for DoS protection
	limiter := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}

	// Build bootstrap peer list before starting the host options
	var bootstrapPeers []peer.AddrInfo
	if bootstrapNodes != "" {
		for _, s := range strings.Split(bootstrapNodes, ",") {
			addr, err := multiaddr.NewMultiaddr(strings.TrimSpace(s))
			if err != nil {
				fmt.Printf("[Bootstrap] Invalid multiaddr %q: %v\n", s, err)
				continue
			}
			info, err := peer.AddrInfoFromP2pAddr(addr)
			if err != nil {
				fmt.Printf("[Bootstrap] Could not parse peer addr %q: %v\n", s, err)
				continue
			}
			bootstrapPeers = append(bootstrapPeers, *info)
		}
	} else {
		// Use the well-known IPFS/libp2p bootstrap nodes
		for _, s := range dht.DefaultBootstrapPeers {
			info, err := peer.AddrInfoFromP2pAddr(s)
			if err != nil {
				continue
			}
			bootstrapPeers = append(bootstrapPeers, *info)
		}
	}

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Identity(priv),
		libp2p.ResourceManager(rm),
		libp2p.NATPortMap(),         // UPnP/NAT-PMP: open ports automatically
		libp2p.EnableHolePunching(), // DCUtR: direct hole-punching through NAT
		// EnableAutoRelay with static relays so it has somewhere to fall back
		libp2p.EnableAutoRelayWithPeerSource(
			func(ctx context.Context, num int) <-chan peer.AddrInfo {
				ch := make(chan peer.AddrInfo)
				go func() {
					defer close(ch)
					for _, p := range bootstrapPeers {
						select {
						case ch <- p:
						case <-ctx.Done():
							return
						}
					}
				}()
				return ch
			},
		),
	)
	if err != nil {
		return err
	}
	n.Host = h

	// Initialize DHT in server mode so this node also helps route others
	kdht, err := dht.New(n.ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}
	n.DHT = kdht

	// Connect to bootstrap peers concurrently BEFORE bootstrapping the DHT
	var wg sync.WaitGroup
	for _, p := range bootstrapPeers {
		wg.Add(1)
		go func(pi peer.AddrInfo) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			defer cancel()
			if err := h.Connect(ctx, pi); err != nil {
				fmt.Printf("[Bootstrap] Failed to connect to %s: %v\n", pi.ID, err)
			} else {
				fmt.Printf("[Bootstrap] Connected to %s\n", pi.ID)
			}
		}(p)
	}
	wg.Wait()

	// Bootstrap DHT AFTER peers are connected so it has routes to walk
	if err := kdht.Bootstrap(n.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}
	fmt.Printf("[Discovery] DHT bootstrap complete, %d peers in peerstore\n", len(h.Peerstore().Peers()))

	ps, err := pubsub.NewGossipSub(n.ctx, n.Host)
	if err != nil {
		return err
	}
	n.PubSub = ps

	topic, err := n.PubSub.Join(DiscoveryTopic)
	if err != nil {
		return err
	}
	n.DiscoveryTopic = topic

	kTopic, err := n.PubSub.Join(KnowledgeDiscoveryTopic)
	if err != nil {
		return err
	}
	n.KnowledgeTopic = kTopic

	sub, err := n.DiscoveryTopic.Subscribe()
	if err != nil {
		return err
	}

	kSub, err := n.KnowledgeTopic.Subscribe()
	if err != nil {
		return err
	}

	go n.discoveryLoop(sub)
	go n.knowledgeDiscoveryLoop(kSub)
	n.SetupHandlers()

	// --- 2. mDNS Discovery (LAN) ---
	// Finds peers on the same local network with zero configuration.
	mdnsService := mdns.NewMdnsService(n.Host, "agentmesh", &mdnsNotifee{h: n.Host})
	if err := mdnsService.Start(); err != nil {
		fmt.Printf("[Discovery] mDNS failed to start (LAN discovery unavailable): %v\n", err)
	} else {
		fmt.Println("[Discovery] mDNS started — will discover peers on local network")
	}

	// --- 3. DHT Namespace Advertising (WAN) ---
	// Advertise under "agentmesh" in the IPFS DHT so any node can find us
	// without needing dedicated AgentMesh bootstrap nodes.
	rd := routing.NewRoutingDiscovery(kdht)
	go func() {
		// Advertise ourselves — retry every 10 minutes as TTL approaches expiry
		for {
			ttl, err := rd.Advertise(n.ctx, "agentmesh")
			if err != nil {
				fmt.Printf("[Discovery] DHT advertise error: %v\n", err)
			}
			select {
			case <-n.ctx.Done():
				return
			case <-time.After(ttl * 4 / 5): // re-advertise at 80% of TTL
			}
		}
	}()
	go n.dhtPeerDiscoveryLoop(rd)

	return nil
}

// mdnsNotifee connects to peers discovered via mDNS.
type mdnsNotifee struct{ h host.Host }

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("[Discovery] mDNS found peer: %s\n", pi.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.h.Connect(ctx, pi); err != nil {
		fmt.Printf("[Discovery] mDNS connect failed: %v\n", err)
	}
}

// dhtPeerDiscoveryLoop finds AgentMesh peers via DHT namespace and connects to them.
func (n *AgentNode) dhtPeerDiscoveryLoop(rd *routing.RoutingDiscovery) {
	// Wait a moment for DHT to settle after bootstrap
	select {
	case <-time.After(5 * time.Second):
	case <-n.ctx.Done():
		return
	}

	for {
		peersCh, err := rd.FindPeers(n.ctx, "agentmesh")
		if err != nil {
			fmt.Printf("[Discovery] DHT FindPeers error: %v\n", err)
		} else {
			for pi := range peersCh {
				if pi.ID == n.Host.ID() {
					continue // skip self
				}
				if n.Host.Network().Connectedness(pi.ID) == network.Connected {
					continue // already connected
				}
				fmt.Printf("[Discovery] DHT found AgentMesh peer: %s\n", pi.ID)
				ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
				if err := n.Host.Connect(ctx, pi); err != nil {
					fmt.Printf("[Discovery] Failed to connect to %s: %v\n", pi.ID, err)
				} else {
					fmt.Printf("[Discovery] Connected to AgentMesh peer: %s\n", pi.ID)
				}
				cancel()
			}
		}
		// Re-scan every 60s
		select {
		case <-time.After(60 * time.Second):
		case <-n.ctx.Done():
			return
		}
	}
}

// loadOrCreateKey loads a persistent Ed25519 key from disk, or generates and saves a new one.
func (n *AgentNode) loadOrCreateKey() (crypto.PrivKey, error) {
	keyPath := filepath.Join(n.workspacePath, "identity.key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		// Key exists — decode and return it
		kBytes, err := crypto.UnmarshalPrivateKey(data)
		if err == nil {
			fmt.Printf("[Identity] Loaded existing key from %s\n", keyPath)
			return kBytes, nil
		}
	}

	// Generate new key
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return nil, err
	}

	// Persist to disk
	encoded, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, encoded, 0600); err != nil {
		// Non-fatal: we still have a key for this session
		fmt.Printf("[Identity] Warning: could not save key to %s: %v\n", keyPath, err)
	} else {
		fmt.Printf("[Identity] Generated new key, saved to %s\n", keyPath)
	}
	return priv, nil
}

func (n *AgentNode) discoveryLoop(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			return
		}

		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}

		var packet SignedPacket
		if err := json.Unmarshal(msg.Data, &packet); err != nil {
			continue
		}

		// Verify signature
		if !n.verifySignature(packet) {
			fmt.Printf("[Security] Rejected packet from %s: invalid signature\n", packet.PeerID)
			continue
		}

		// Data is now a JSON string, parse it
		var data struct {
			Capability AgentCapability `json:"capability"`
			EthAddress string          `json:"ethAddress,omitempty"`
		}
		if err := json.Unmarshal([]byte(packet.Data), &data); err != nil {
			continue
		}

		// Reputation check (if configured)
		n.mu.RLock()
		checker := n.reputationChecker
		n.mu.RUnlock()

		if checker != nil && data.EthAddress != "" {
			reputable, err := checker(packet.PeerID, data.EthAddress)
			if err != nil || !reputable {
				fmt.Printf("[Reputation] Rejected agent %s (Eth: %s): low or invalid reputation\n", packet.PeerID, data.EthAddress)
				continue
			}
		}

		n.mu.RLock()
		callbacks := make([]CapabilityCallback, len(n.onCapCallbacks))
		copy(callbacks, n.onCapCallbacks)
		n.mu.RUnlock()

		for _, cb := range callbacks {
			cb(packet.PeerID, data.Capability)
		}
	}
}

// signData signs the data using the node's private key.
func (n *AgentNode) signData(data []byte) (string, error) {
	rawKey, err := n.privKey.Raw()
	if err != nil {
		return "", err
	}
	// Ed25519 private key is 64 bytes (seed + public key), but crypto/ed25519 expects 64 bytes
	privKey := ed25519.PrivateKey(rawKey)
	sig := ed25519.Sign(privKey, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifySignature verifies the signature on a SignedPacket.
func (n *AgentNode) verifySignature(packet SignedPacket) bool {
	// Decode the PeerID to get the public key
	pid, err := peer.Decode(packet.PeerID)
	if err != nil {
		return false
	}

	pubKey, err := pid.ExtractPublicKey()
	if err != nil {
		return false
	}

	rawPub, err := pubKey.Raw()
	if err != nil {
		return false
	}

	sig, err := base64.StdEncoding.DecodeString(packet.Signature)
	if err != nil {
		return false
	}

	// Data is now stored as the exact JSON string that was signed
	return ed25519.Verify(rawPub, []byte(packet.Data), sig)
}

func (n *AgentNode) OnCapability(cb CapabilityCallback) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onCapCallbacks = append(n.onCapCallbacks, cb)
}

func (n *AgentNode) AdvertiseCapability(capability AgentCapability) {
	n.AdvertiseCapabilityWithEth(capability, "")
}

// AdvertiseCapabilityWithEth advertises with an optional Ethereum address for reputation lookup.
func (n *AgentNode) AdvertiseCapabilityWithEth(capability AgentCapability, ethAddress string) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		broadcast := func() {
			data := map[string]interface{}{
				"capability": capability,
				"timestamp":  time.Now().UnixMilli(),
			}
			if ethAddress != "" {
				data["ethAddress"] = ethAddress
			}

			dataBytes, _ := json.Marshal(data)
			sig, err := n.signData(dataBytes)
			if err != nil {
				fmt.Printf("[Signing Error] %v\n", err)
				return
			}

			packet := SignedPacket{
				Data:      string(dataBytes), // Store as string for deterministic verification
				PeerID:    n.Host.ID().String(),
				Signature: sig,
			}
			bytes, _ := json.Marshal(packet)
			n.DiscoveryTopic.Publish(n.ctx, bytes)
		}

		broadcast()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				broadcast()
			}
		}
	}()
}

func (n *AgentNode) SetupHandlers() {
	n.Host.SetStreamHandler(protocol.ID(TaskProtocol), func(s network.Stream) {
		defer s.Close()

		data, err := readLP(s)
		if err != nil {
			return
		}

		var msg AgentMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			return
		}

		if msg.Type == "task" {
			response := AgentMessage{
				Type: "response",
				Payload: map[string]interface{}{
					"status":  "success",
					"agent":   n.Host.ID().String(),
					"message": "Task processed successfully",
				},
				Sender:    n.Host.ID().String(),
				Timestamp: time.Now().UnixMilli(),
			}
			respBytes, _ := json.Marshal(response)
			writeLP(s, respBytes)
		}
	})

	n.Host.SetStreamHandler(protocol.ID(MemoryProtocol), func(s network.Stream) {
		defer s.Close()

		data, err := readLP(s)
		if err != nil {
			return
		}

		var req struct {
			Type      string `json:"type"`
			TopicHash string `json:"topicHash"`
		}
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}

		if req.Type == "get_memory" {
			chunk, err := n.Memory.GetMemory(req.TopicHash)
			if err == nil && chunk != nil {
				respBytes, _ := json.Marshal(chunk)
				writeLP(s, respBytes)
			}
		}
	})
}

func (n *AgentNode) knowledgeDiscoveryLoop(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(n.ctx)
		if err != nil {
			return
		}

		if msg.ReceivedFrom == n.Host.ID() {
			continue
		}

		var query KnowledgeDiscoveryMsg
		if err := json.Unmarshal(msg.Data, &query); err != nil {
			continue
		}

		fmt.Printf("[Memory] Received discovery query: %q from %s\n", query.Query, query.Requester)

		// Check local memory for matches
		var matches []MemoryChunk
		n.Memory.mu.RLock()
		for _, tag := range query.Tags {
			newMatches, err := n.Memory.Search(tag)
			if err != nil {
				continue
			}
			matches = append(matches, newMatches...)
		}
		n.Memory.mu.RUnlock()

		if len(matches) > 0 {
			fmt.Printf("[Memory] Found %d potential matches for %q\n", len(matches), query.Query)
			// TODO: Implementation of KnowledgeOffers for automated P2P trading
		}
	}
}

func (n *AgentNode) SendTask(ctx context.Context, targetAddr string, payload interface{}) (interface{}, error) {
	info, err := peer.AddrInfoFromString(targetAddr)
	var pid peer.ID
	if err != nil {
		pid, err = peer.Decode(targetAddr)
		if err != nil {
			return nil, err
		}
	} else {
		pid = info.ID
		n.Host.Peerstore().AddAddrs(pid, info.Addrs, time.Hour)
	}

	s, err := n.Host.NewStream(ctx, pid, protocol.ID(TaskProtocol))
	if err != nil {
		return nil, err
	}
	defer s.Close()

	msg := AgentMessage{
		Type:      "task",
		Payload:   payload,
		Sender:    n.Host.ID().String(),
		Timestamp: time.Now().UnixMilli(),
	}

	bytes, _ := json.Marshal(msg)
	if err := writeLP(s, bytes); err != nil {
		return nil, err
	}

	respBytes, err := readLP(s)
	if err != nil {
		return nil, err
	}

	var resp AgentMessage
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return nil, err
	}

	return resp.Payload, nil
}

func (n *AgentNode) Stop() error {
	n.cancel()
	return n.Host.Close()
}

// Helpers

func readLP(r io.Reader) ([]byte, error) {
	br := &byteReader{r}
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

func writeLP(w io.Writer, data []byte) error {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, uint64(len(data)))
	if _, err := w.Write(buf[:n]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

type byteReader struct {
	io.Reader
}

func (br *byteReader) ReadByte() (byte, error) {
	var b [1]byte
	n, err := br.Reader.Read(b[:])
	if n == 1 {
		return b[0], nil
	}
	if err == nil {
		err = io.EOF
	}
	return 0, err
}
