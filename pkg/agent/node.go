package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/libp2p/go-libp2p/p2p/host/autonat"
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
}

func NewAgentNode(dbPath string, workspacePath string) (*AgentNode, error) {
	ctx, cancel := context.WithCancel(context.Background())
	store, err := NewMemoryStore(dbPath, workspacePath)
	if err != nil {
		cancel()
		return nil, err
	}
	return &AgentNode{
		ctx:    ctx,
		cancel: cancel,
		Memory: store,
	}, nil
}

// SetReputationChecker sets a custom function that is called to verify an agent's reputation.
func (n *AgentNode) SetReputationChecker(checker ReputationChecker) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.reputationChecker = checker
}

func (n *AgentNode) Start(listenAddr string, bootstrapNodes string) error {
	// Generate or load identity
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	n.privKey = priv

	// Resource Manager for DoS protection
	limiter := rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(limiter)
	if err != nil {
		return fmt.Errorf("failed to create resource manager: %w", err)
	}

	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.Identity(priv),
		libp2p.ResourceManager(rm),
		libp2p.NATPortMap(),         // Enable NAT traversal (UPnP/NAT-PMP)
		libp2p.EnableRelay(),        // Enable circuit relay
		libp2p.EnableHolePunching(), // Enable DCUtR hole punching
		libp2p.EnableAutoRelay(),    // Use default relays automatically
	)
	if err != nil {
		return err
	}
	n.Host = h

	// AutoNAT helps the node understand its reachability
	_, err = autonat.New(h)
	if err != nil {
		fmt.Printf("[Connectivity] Failed to start AutoNAT: %v\n", err)
	}

	// Initialize DHT
	kdht, err := dht.New(n.ctx, h)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}
	n.DHT = kdht

	if err := kdht.Bootstrap(n.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Handle Boostrap Nodes
	var peers []peer.AddrInfo
	if bootstrapNodes != "" {
		for _, s := range strings.Split(bootstrapNodes, ",") {
			addr, err := multiaddr.NewMultiaddr(strings.TrimSpace(s))
			if err != nil {
				continue
			}
			info, err := peer.AddrInfoFromP2pAddr(addr)
			if err != nil {
				continue
			}
			peers = append(peers, *info)
		}
	} else {
		// Default libp2p bootstrap nodes
		for _, s := range dht.DefaultBootstrapPeers {
			info, err := peer.AddrInfoFromP2pAddr(s)
			if err != nil {
				continue
			}
			peers = append(peers, *info)
		}
	}

	for _, p := range peers {
		if err := h.Connect(n.ctx, p); err != nil {
			fmt.Printf("[Discovery] Failed to connect to bootstrap node %s: %v\n", p.ID, err)
		} else {
			fmt.Printf("[Discovery] Connected to bootstrap node %s\n", p.ID)
		}
	}

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

	return nil
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
