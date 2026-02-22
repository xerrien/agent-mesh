package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agentmesh/pkg/agent"

	"github.com/ethereum/go-ethereum/common"
)

func main() {
	fmt.Println("Starting AgentMesh Go Demo (Phase 5 & 6)...")

	// --- Setup ERC-8004 Registry Addresses (Base Sepolia Examples) ---
	identityRegistry := "0x7274e874ca62410a93bd8bf61c69d8045e399c02"
	reputationRegistry := "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"
	validationRegistry := "0x0000000000000000000000000000000000000000" // Placeholder

	reputationClient := agent.NewERC8004Client(
		"https://sepolia.base.org", // Use Sepolia if testing
		identityRegistry,
		reputationRegistry,
		validationRegistry,
	)

	// --- Initialize Agents with Independent Persistent Databases & OpenClaw Workspaces ---
	os.MkdirAll("./agent_a_workspace", 0755)
	os.MkdirAll("./agent_b_workspace", 0755)

	// Create a sample OpenClaw memory file for Agent A
	err := os.WriteFile("./agent_a_workspace/ProtocolTreasury_Audit.md", []byte("# ProtocolTreasury Audit\nStatus: SECURE\nDetailed audit logs showing 0 vulnerabilities in ProtocolTreasury.sol."), 0644)
	if err != nil {
		log.Fatalf("Failed to create sample memory: %v", err)
	}

	agentA, err := agent.NewAgentNode("agent_a_metadata.db", "./agent_a_workspace")
	if err != nil {
		log.Fatalf("Failed to init Agent A: %v", err)
	}
	agentB, err := agent.NewAgentNode("agent_b_metadata.db", "./agent_b_workspace")
	if err != nil {
		log.Fatalf("Failed to init Agent B: %v", err)
	}

	// --- Setup Blockchain Watcher for Agent A ---
	// Agent A will "watch" for tasks and knowledge queries on-chain and react.
	watcher, err := agent.NewEventWatcher(
		"https://sepolia.base.org",
		"0x0000000000000000000000000000000000000000", // TaskEscrow placeholder
		"0x0000000000000000000000000000000000000000", // KnowledgeMarket placeholder
		func(e agent.TaskCreatedEvent) {
			fmt.Printf("[Watcher] >>> ON-CHAIN TASK DETECTED: ID=%s, Payment=%s\n", e.TaskId, e.Payment)
			fmt.Println("[Agent A] Task found on-chain! Advertising capability to handle it...")
		},
		func(q agent.KnowledgeRequestedEvent) {
			fmt.Printf("[Watcher] >>> ON-CHAIN KNOWLEDGE REQUEST: %s (%s)\n", q.Topic, q.Bounty)
			fmt.Println("[Agent A] Resolving identity from ERC-8004 Registry...")

			// We use the reputationClient created earlier in the demo for resolution
			if reputationClient != nil {
				agentId, err := reputationClient.GetAgentIdByWallet(q.Requester)
				if err == nil {
					peerId, _ := reputationClient.GetMetadata(agentId, "peerId")
					if peerId != "" {
						fmt.Printf("[Agent A] Successfully resolved Nostr pubkey: %s\n", peerId)
						fmt.Println("[Agent A] Reacting to on-chain knowledge demand via Nostr...")
					}
				}
			}
		},
	)
	if err == nil {
		agentA.Watcher = watcher
		go agentA.Watcher.Start(context.Background())
	}

	fmt.Println("Starting Agent A...")
	if err := agentA.Start("", "wss://relay.damus.io,wss://nos.lol"); err != nil {
		log.Fatalf("Failed to start Agent A: %v", err)
	}
	defer agentA.Stop()

	fmt.Println("Starting Agent B...")
	if err := agentB.Start("", "wss://relay.damus.io,wss://nos.lol"); err != nil {
		log.Fatalf("Failed to start Agent B: %v", err)
	}
	defer agentB.Stop()

	// Connect B to A by Nostr pubkey
	_ = agentB.ConnectPeer(context.Background(), agentA.NodeID())

	// --- Reputation Check Simulation ---
	agentB.SetReputationChecker(func(pid string, eth string) (bool, error) {
		fmt.Printf("[Reputation] Checking agent %s for wallet %s...\n", pid, eth)
		// We use the new v2.0.0 GetReputationSummary with the agent's own wallet
		agentID := big.NewInt(1) // Example AgentID
		count, value, _, err := reputationClient.GetReputationSummary(agentID, "audit", "", common.HexToAddress("0x0000000000000000000000000000000000000000"))
		if err != nil {
			fmt.Printf("[Reputation] Query failed: %v\n", err)
			return true, nil
		}
		fmt.Printf("[Reputation] Agent ID %d has %d signals, summary: %s\n", agentID, count, value)
		return true, nil
	})

	agentB.OnCapability(func(peerID string, cap agent.AgentCapability) {
		fmt.Printf("[Agent B] >>> DISCOVERED capability: %s from %s\n", cap.Name, peerID)

		if cap.Name == "search" {
			fmt.Println("[Agent B] Need knowledge about 'treasury'. Broadcasting discovery query...")
			discoveryMsg := agent.KnowledgeDiscoveryMsg{
				Query:     "Need audit info for treasury",
				Tags:      []string{"audit", "treasury"},
				Requester: agentB.NodeID(),
				Timestamp: time.Now().UnixMilli(),
			}
			msgBytes, _ := jsonMarshal(discoveryMsg)
			var msg agent.KnowledgeDiscoveryMsg
			_ = json.Unmarshal(msgBytes, &msg)
			_ = agentB.PublishKnowledgeQuery(msg)
		}
	})

	time.Sleep(1 * time.Second)
	fmt.Println("[Demo] Agent B initiating Knowledge Discovery for tags [audit, treasury]...")

	// Agent B broadcasts knowledge query
	discoveryMsg := agent.KnowledgeDiscoveryMsg{
		Query:     "Need audit info for treasury",
		Tags:      []string{"audit", "treasury"},
		Requester: agentB.NodeID(),
		Timestamp: time.Now().UnixMilli(),
	}
	_ = agentB.PublishKnowledgeQuery(discoveryMsg)

	// Keep alive
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
