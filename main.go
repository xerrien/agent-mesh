package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agentmesh/pkg/agent"
)

func main() {
	const defaultWorkspace = "./workspace"
	dbPath := flag.String("db", "agent_metadata.db", "Path to metadata database")
	workspace := flag.String("workspace", defaultWorkspace, "Workspace directory (stores nostr.key and local memory files)")
	listenAddr := flag.String("listen", "", "Deprecated. Ignored in Nostr mode.")
	rpcURL := flag.String("rpc", "wss://base-sepolia.drpc.org", "Ethereum RPC URL")
	escrowAddr := flag.String("escrow", "0x591ee5158c94d736ce9bf544bc03247d14904061", "TaskEscrow contract address")
	identAddr := flag.String("identity", "0x8004A818BFB912233c491871b3d84c89A494BD9e", "ERC-8004 IdentityRegistry address")
	reputAddr := flag.String("reputation", "0x8004B663056A597Dffe9eCcC1965A193B7388713", "ERC-8004 ReputationRegistry address")
	bootstrapNodes := flag.String("bootstrap", "wss://nos.lol", "Comma-separated Nostr relay URLs (wss://...)")
	flag.Parse()

	fmt.Printf("Starting AgentMesh Node...\n")
	fmt.Printf("Database: %s\n", *dbPath)
	fmt.Printf("Workspace: %s\n", *workspace)

	// Ensure workspace exists
	os.MkdirAll(*workspace, 0755)

	node, err := agent.NewAgentNode(*dbPath, *workspace)
	if err != nil {
		log.Fatalf("Failed to initialize node: %v", err)
	}

	chainRequired := map[string]string{
		"-rpc":      *rpcURL,
		"-escrow":   *escrowAddr,
		"-identity": *identAddr,
	}
	missingChainFlags := make([]string, 0, len(chainRequired))
	anyChainFlag := false
	for name, value := range chainRequired {
		if strings.TrimSpace(value) == "" {
			missingChainFlags = append(missingChainFlags, name)
		} else {
			anyChainFlag = true
		}
	}
	if strings.TrimSpace(*reputAddr) != "" {
		anyChainFlag = true
	}

	if len(missingChainFlags) == 0 {
		node.ERCClient = agent.NewERC8004Client(*rpcURL, *identAddr, *reputAddr, "0x0000000000000000000000000000000000000000")
		fmt.Println("[Startup] ERC identity/reputation client enabled")
	} else if anyChainFlag {
		fmt.Printf("[Startup] Partial chain config detected (missing %s). Continuing in Nostr-only mode.\n", strings.Join(missingChainFlags, ", "))
	} else {
		fmt.Println("[Startup] No chain config provided. Running in Nostr-only mode.")
	}

	if err := node.Start(*listenAddr, *bootstrapNodes); err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}

	fmt.Printf("Node started! Nostr pubkey: %s\n", node.NodeID())
	fmt.Printf("Relays: %v\n", node.RelayURLs())
	fmt.Println("Operator console: connect <pubkey> | msg <pubkey> <text> (encrypted) | task <pubkey> <json-or-text> | query <query text> [| tag1,tag2] | advertise <name> [description] | advertise-loop <name> [ttlSec] [description] | unadvertise <name> | ask <pubkey> <task> | askall <task> | gossip <pubkey> [limit] | inbox [limit] | inbox-read [limit] | inbox-ack <eventID> | peers | help")
	go operatorConsole(node)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	node.Stop()
	fmt.Println("Node stopped.")
}

func operatorConsole(node *agent.AgentNode) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		switch strings.ToLower(parts[0]) {
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  connect <pubkey>")
			fmt.Println("  msg <pubkey> <text>  # encrypted via NIP-44")
			fmt.Println("  task <pubkey> <json-or-text>")
			fmt.Println("  query <query text> [| tag1,tag2]")
			fmt.Println("  advertise <name> [description]")
			fmt.Println("  advertise-loop <name> [ttlSec] [description]")
			fmt.Println("  unadvertise <name>")
			fmt.Println("  ask <pubkey> <task>")
			fmt.Println("  askall <task>")
			fmt.Println("  gossip <pubkey> [limit]")
			fmt.Println("  inbox [limit]")
			fmt.Println("  inbox-read [limit]")
			fmt.Println("  inbox-ack <eventID>")
			fmt.Println("  peers")
			fmt.Println("  help")
		case "peers":
			peers := node.ConnectedPeers()
			if len(peers) == 0 {
				fmt.Println("[Operator] No connected peers")
				continue
			}
			fmt.Printf("[Operator] Connected peers (%d):\n", len(peers))
			for _, p := range peers {
				fmt.Printf("- %s\n", p)
			}
		case "connect":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: connect <pubkey>")
				continue
			}
			target := parts[1]
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := node.ConnectPeer(ctx, target)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Connect failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Peer reachable via relay: %s\n", target)
		case "msg":
			if len(parts) < 3 {
				fmt.Println("[Operator] Usage: msg <pubkey> <text>")
				continue
			}
			target := parts[1]
			text := strings.TrimSpace(strings.Join(parts[2:], " "))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			resp, err := node.SendMessage(ctx, target, text)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Message failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Message delivered to %s (ack: %v)\n", target, resp)
		case "task":
			if len(parts) < 3 {
				fmt.Println("[Operator] Usage: task <pubkey> <json-or-text>")
				continue
			}
			target := parts[1]
			payloadRaw := strings.TrimSpace(strings.Join(parts[2:], " "))
			payload := parseTaskPayload(payloadRaw)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resp, err := node.SendTask(ctx, target, payload)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Task send failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Task response from %s: %v\n", target, resp)
		case "query":
			raw := strings.TrimSpace(strings.TrimPrefix(line, parts[0]))
			query, tags, err := parseQueryCommand(raw)
			if err != nil {
				fmt.Printf("[Operator] %v\n", err)
				fmt.Println("[Operator] Usage: query <query text> [| tag1,tag2]")
				continue
			}
			msg := agent.KnowledgeDiscoveryMsg{
				Query:     query,
				Tags:      tags,
				Requester: node.NodeID(),
				Timestamp: time.Now().UnixMilli(),
			}
			if err := node.PublishKnowledgeQuery(msg); err != nil {
				fmt.Printf("[Operator] Query publish failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Knowledge query published: %q (tags=%v)\n", query, tags)
		case "advertise":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: advertise <name> [description]")
				continue
			}
			name, desc := parseAdvertiseOnceArgs(parts)
			if name == "" {
				fmt.Println("[Operator] Usage: advertise <name> [description]")
				continue
			}
			if err := node.PublishCapability(agent.AgentCapability{
				Name:        name,
				Description: desc,
			}); err != nil {
				fmt.Printf("[Operator] Advertise failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Published capability %q once\n", name)
		case "advertise-loop":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: advertise-loop <name> [ttlSec] [description]")
				continue
			}
			name, ttl, desc, err := parseAdvertiseArgs(parts)
			if err != nil {
				fmt.Printf("[Operator] %v\n", err)
				fmt.Println("[Operator] Usage: advertise-loop <name> [ttlSec] [description]")
				continue
			}
			node.AdvertiseCapabilityFor(agent.AgentCapability{
				Name:        name,
				Description: desc,
			}, "", ttl)
			fmt.Printf("[Operator] Advertising capability %q every 10s for %s\n", name, ttl)
		case "unadvertise":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: unadvertise <name>")
				continue
			}
			if node.StopAdvertising(parts[1]) {
				fmt.Printf("[Operator] Stopped advertising %q\n", strings.TrimSpace(parts[1]))
			} else {
				fmt.Printf("[Operator] No active advertisement found for %q\n", strings.TrimSpace(parts[1]))
			}
		case "ask":
			if len(parts) < 3 {
				fmt.Println("[Operator] Usage: ask <pubkey> <task>")
				continue
			}
			target := parts[1]
			task := strings.TrimSpace(strings.Join(parts[2:], " "))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			providers, err := node.QueryPeerForTaskProviders(ctx, target, task)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Provider lookup failed: %v\n", err)
				continue
			}
			if len(providers) == 0 {
				fmt.Printf("[Operator] %s returned no known providers for %q\n", target, task)
				continue
			}
			fmt.Printf("[Operator] Providers from %s for %q:\n", target, task)
			for _, p := range providers {
				fmt.Printf("- %s\n", p)
			}
		case "askall":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: askall <task>")
				continue
			}
			task := strings.TrimSpace(strings.Join(parts[1:], " "))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			providers, err := node.QueryKnownPeersForTaskProviders(ctx, task)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Provider lookup failed: %v\n", err)
				continue
			}
			if len(providers) == 0 {
				fmt.Printf("[Operator] No providers found for %q\n", task)
				continue
			}
			fmt.Printf("[Operator] Providers for %q:\n", task)
			for _, p := range providers {
				fmt.Printf("- %s\n", p)
			}
		case "gossip":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: gossip <pubkey> [limit]")
				continue
			}
			target := parts[1]
			limit := 64
			if len(parts) > 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil && n > 0 {
					limit = n
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			peers, err := node.RequestPeerExchange(ctx, target, limit)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Gossip failed: %v\n", err)
				continue
			}
			if len(peers) == 0 {
				fmt.Printf("[Operator] %s returned no peer hints\n", target)
				continue
			}
			fmt.Printf("[Operator] Received %d peer hints from %s:\n", len(peers), target)
			for _, peer := range peers {
				fmt.Printf("- %s relays=%d caps=%d\n", peer.PubKey, len(peer.Relays), len(peer.Capabilities))
			}
		case "inbox":
			limit := 20
			if len(parts) > 1 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && n > 0 {
					limit = n
				}
			}
			items, err := node.InboxEvents(limit)
			if err != nil {
				fmt.Printf("[Operator] Inbox read failed: %v\n", err)
				continue
			}
			if len(items) == 0 {
				fmt.Println("[Operator] Inbox is empty")
				continue
			}
			fmt.Printf("[Operator] Inbox events (%d):\n", len(items))
			for _, it := range items {
				status := "pending"
				if it.ProcessedAt > 0 {
					status = fmt.Sprintf("acked@%d", it.ProcessedAt)
				}
				fmt.Printf("- kind=%d sender=%s relay=%s created=%d id=%s status=%s\n", it.Kind, it.Sender, it.RelayURL, it.CreatedAt, it.EventID, status)
			}
		case "inbox-read":
			limit := 20
			if len(parts) > 1 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && n > 0 {
					limit = n
				}
			}
			items, err := node.UnreadInboxEvents(limit)
			if err != nil {
				fmt.Printf("[Operator] Inbox unread read failed: %v\n", err)
				continue
			}
			if len(items) == 0 {
				fmt.Println("[Operator] Inbox unread is empty")
				continue
			}
			fmt.Printf("[Operator] Inbox unread events (%d):\n", len(items))
			for _, it := range items {
				fmt.Printf("- kind=%d sender=%s relay=%s created=%d id=%s\n", it.Kind, it.Sender, it.RelayURL, it.CreatedAt, it.EventID)
			}
		case "inbox-ack":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: inbox-ack <eventID>")
				continue
			}
			ok, err := node.AckInboxEvent(parts[1])
			if err != nil {
				fmt.Printf("[Operator] Inbox ack failed: %v\n", err)
				continue
			}
			if !ok {
				fmt.Printf("[Operator] Inbox ack no-op (not found or already acked): %s\n", parts[1])
				continue
			}
			fmt.Printf("[Operator] Inbox event acked: %s\n", parts[1])
		default:
			fmt.Printf("[Operator] Unknown command: %s (try: help)\n", parts[0])
		}
	}
}

func parseTaskPayload(raw string) interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var decoded interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
		return decoded
	}
	return raw
}

func parseQueryCommand(raw string) (string, []string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("query cannot be empty")
	}

	queryPart := raw
	tagsPart := ""
	if idx := strings.Index(raw, "|"); idx >= 0 {
		queryPart = strings.TrimSpace(raw[:idx])
		tagsPart = strings.TrimSpace(raw[idx+1:])
	}
	if queryPart == "" {
		return "", nil, fmt.Errorf("query cannot be empty")
	}

	var tags []string
	if tagsPart != "" {
		for _, t := range strings.Split(tagsPart, ",") {
			tag := strings.TrimSpace(t)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	return queryPart, tags, nil
}

func parseAdvertiseArgs(parts []string) (string, time.Duration, string, error) {
	name := strings.TrimSpace(parts[1])
	if name == "" {
		return "", 0, "", fmt.Errorf("capability name cannot be empty")
	}
	ttl := 2 * time.Minute
	descStart := 2
	if len(parts) > 2 {
		if secs, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil {
			if secs <= 0 {
				return "", 0, "", fmt.Errorf("ttlSec must be greater than 0")
			}
			ttl = time.Duration(secs) * time.Second
			descStart = 3
		}
	}
	desc := ""
	if len(parts) > descStart {
		desc = strings.TrimSpace(strings.Join(parts[descStart:], " "))
	}
	return name, ttl, desc, nil
}

func parseAdvertiseOnceArgs(parts []string) (string, string) {
	name := strings.TrimSpace(parts[1])
	if name == "" {
		return "", ""
	}
	desc := ""
	if len(parts) > 2 {
		desc = strings.TrimSpace(strings.Join(parts[2:], " "))
	}
	return name, desc
}
