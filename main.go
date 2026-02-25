package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/pelletier/go-toml/v2"
)

type startupCapabilityConfig struct {
	Name        string `toml:"name"`
	Description string `toml:"description"`
	Loop        bool   `toml:"loop"`
	TTLSec      int    `toml:"ttl_sec"`
}

type startupMCPRateConfig struct {
	Tool      string `toml:"tool"`
	Limit     int    `toml:"limit"`
	WindowSec int64  `toml:"window_sec"`
}

type startupMCPACLConfig struct {
	Tool  string   `toml:"tool"`
	Peers []string `toml:"peers"`
}

type startupProfile struct {
	Headless                bool                      `toml:"headless"`
	Bootstrap               string                    `toml:"bootstrap"`
	AutoConnect             []string                  `toml:"auto_connect"`
	BlockedPeers            []string                  `toml:"blocked_peers"`
	AutoAdvertise           []startupCapabilityConfig `toml:"auto_advertise"`
	ControlListen           string                    `toml:"control_listen"`
	ControlToken            string                    `toml:"control_token"`
	MCPDefaultRateLimit     int                       `toml:"mcp_default_rate_limit"`
	MCPDefaultRateWindowSec int64                     `toml:"mcp_default_rate_window_sec"`
	MCPACLDefaultDeny       *bool                     `toml:"mcp_acl_default_deny"`
	MCPToolRates            []startupMCPRateConfig    `toml:"mcp_tool_rates"`
	MCPToolACL              []startupMCPACLConfig     `toml:"mcp_tool_acl"`
}

const (
	operatorConnectTimeout = 20 * time.Second
	operatorSendTimeout    = 30 * time.Second
	startupConnectTimeout  = 20 * time.Second
)

func main() {
	const defaultWorkspace = "./workspace"
	dbPath := flag.String("db", "agent_metadata.db", "Path to metadata database")
	workspace := flag.String("workspace", defaultWorkspace, "Workspace directory (stores nostr.key and local memory files)")
	listenAddr := flag.String("listen", "", "Deprecated. Ignored in Nostr mode.")
	configPath := flag.String("config", "", "Optional path to startup profile TOML")
	headless := flag.Bool("headless", false, "Run without interactive operator console")
	controlListen := flag.String("control-listen", "", "Optional local control API listen address (for example 127.0.0.1:8787)")
	controlToken := flag.String("control-token", "", "Optional control API token (sent in X-AgentMesh-Token)")
	rpcURL := flag.String("rpc", "https://mainnet.base.org", "Ethereum RPC URL")
	escrowAddr := flag.String("escrow", "0xE45b6a75051AFb109dd60D262D7AF111957487B1", "TaskEscrow contract address")
	identAddr := flag.String("identity", "0x8004A818BFB912233c491871b3d84c89A494BD9e", "ERC-8004 IdentityRegistry address")
	reputAddr := flag.String("reputation", "0x8004B663056A597Dffe9eCcC1965A193B7388713", "ERC-8004 ReputationRegistry address")
	bootstrapNodes := flag.String("bootstrap", "wss://nos.lol", "Comma-separated Nostr relay URLs (wss://...)")
	flag.Parse()

	profile, err := loadStartupProfile(*configPath)
	if err != nil {
		log.Fatalf("Failed to load startup profile: %v", err)
	}
	if profile != nil && strings.TrimSpace(profile.Bootstrap) != "" {
		*bootstrapNodes = strings.TrimSpace(profile.Bootstrap)
	}
	if profile != nil && strings.TrimSpace(profile.ControlListen) != "" {
		*controlListen = strings.TrimSpace(profile.ControlListen)
	}
	if profile != nil && strings.TrimSpace(profile.ControlToken) != "" {
		*controlToken = strings.TrimSpace(profile.ControlToken)
	}
	runHeadless := *headless
	if profile != nil && profile.Headless {
		runHeadless = true
	}

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
	if err := applyStartupProfile(node, profile); err != nil {
		fmt.Printf("[Startup] Profile actions completed with warnings: %v\n", err)
	}

	var controlServer *controlAPIServer
	if strings.TrimSpace(*controlListen) != "" {
		if strings.TrimSpace(*controlToken) == "" {
			log.Fatalf("Refusing to start control API without token. Set --control-token when using --control-listen.")
		}
		if !isLikelyLoopbackAddr(strings.TrimSpace(*controlListen)) {
			fmt.Printf("[Startup] Warning: control API is not bound to loopback (%s). Prefer 127.0.0.1 or localhost.\n", strings.TrimSpace(*controlListen))
		}
		srv, err := startControlAPI(strings.TrimSpace(*controlListen), node, strings.TrimSpace(*controlToken))
		if err != nil {
			log.Fatalf("Failed to start control API: %v", err)
		}
		controlServer = srv
		fmt.Printf("[Startup] Control API listening on http://%s\n", strings.TrimSpace(*controlListen))
	}

	fmt.Printf("Node started! Nostr pubkey: %s\n", node.NodeID())
	fmt.Printf("Relays: %v\n", node.RelayURLs())
	if runHeadless {
		fmt.Println("[Startup] Headless mode enabled: operator console disabled")
	} else {
		fmt.Println("Operator console: connect <pubkey> | send <pubkey> <type> <json> | block <pubkey> | unblock <pubkey> | blocked | peers | inbox [limit] | inbox-read [limit] | inbox-ack <eventID> | help")
		go operatorConsole(node)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	if controlServer != nil {
		_ = controlServer.Stop()
	}
	node.Stop()
	fmt.Println("Node stopped.")
}

func loadStartupProfile(path string) (*startupProfile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var profile startupProfile
	if err := toml.Unmarshal(b, &profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func applyStartupProfile(node *agent.AgentNode, profile *startupProfile) error {
	if profile == nil {
		return nil
	}
	var errs []string
	if profile.MCPDefaultRateLimit > 0 && profile.MCPDefaultRateWindowSec > 0 {
		if err := node.SetMCPDefaultRateLimit(profile.MCPDefaultRateLimit, time.Duration(profile.MCPDefaultRateWindowSec)*time.Second); err != nil {
			errs = append(errs, fmt.Sprintf("mcp default rate: %v", err))
		} else {
			fmt.Printf("[Startup] MCP default rate limit: %d per %ds\n", profile.MCPDefaultRateLimit, profile.MCPDefaultRateWindowSec)
		}
	}
	if profile.MCPACLDefaultDeny != nil {
		if err := node.SetMCPACLDefaultDeny(*profile.MCPACLDefaultDeny); err != nil {
			errs = append(errs, fmt.Sprintf("mcp acl default deny: %v", err))
		} else {
			fmt.Printf("[Startup] MCP ACL default deny: %t\n", *profile.MCPACLDefaultDeny)
		}
	}
	for _, entry := range profile.MCPToolRates {
		tool := strings.TrimSpace(entry.Tool)
		if tool == "" {
			continue
		}
		if err := node.SetMCPToolRateLimit(tool, entry.Limit, time.Duration(entry.WindowSec)*time.Second); err != nil {
			errs = append(errs, fmt.Sprintf("mcp tool rate %s: %v", tool, err))
			continue
		}
		fmt.Printf("[Startup] MCP rate limit for %q: %d per %ds\n", tool, entry.Limit, entry.WindowSec)
	}
	for _, entry := range profile.MCPToolACL {
		tool := strings.TrimSpace(entry.Tool)
		if tool == "" {
			continue
		}
		for _, peer := range entry.Peers {
			peer = strings.TrimSpace(peer)
			if peer == "" {
				continue
			}
			if err := node.AllowMCPToolCaller(tool, peer); err != nil {
				errs = append(errs, fmt.Sprintf("mcp acl %s->%s: %v", tool, peer, err))
				continue
			}
			fmt.Printf("[Startup] MCP ACL allow %q -> %s\n", tool, peer)
		}
	}

	for _, peer := range profile.BlockedPeers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		if err := node.BlockPeer(peer); err != nil {
			errs = append(errs, fmt.Sprintf("block %s: %v", peer, err))
			continue
		}
		fmt.Printf("[Startup] Blocked peer: %s\n", peer)
	}

	for _, capCfg := range profile.AutoAdvertise {
		name := strings.TrimSpace(capCfg.Name)
		if name == "" {
			continue
		}
		cap := agent.AgentCapability{
			Name:        name,
			Description: strings.TrimSpace(capCfg.Description),
		}
		if capCfg.Loop {
			ttl := 2 * time.Minute
			if capCfg.TTLSec > 0 {
				ttl = time.Duration(capCfg.TTLSec) * time.Second
			}
			node.AdvertiseCapabilityFor(cap, "", ttl)
			fmt.Printf("[Startup] Auto-advertising capability %q for %s\n", cap.Name, ttl)
			continue
		}
		if err := node.PublishCapability(cap); err != nil {
			errs = append(errs, fmt.Sprintf("advertise %s: %v", cap.Name, err))
			continue
		}
		fmt.Printf("[Startup] Published capability %q once\n", cap.Name)
	}

	for _, peer := range profile.AutoConnect {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), startupConnectTimeout)
		err := node.ConnectPeer(ctx, peer)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Sprintf("connect %s: %v", peer, err))
			continue
		}
		fmt.Printf("[Startup] Auto-connected peer: %s\n", peer)
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
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
			fmt.Println("  send <pubkey> <type> <json>")
			fmt.Println("  block <pubkey>")
			fmt.Println("  unblock <pubkey>")
			fmt.Println("  blocked")
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
			ctx, cancel := context.WithTimeout(context.Background(), operatorConnectTimeout)
			err := node.ConnectPeer(ctx, target)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Connect failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Peer reachable via relay: %s\n", target)
		case "send":
			if len(parts) < 4 {
				fmt.Println("[Operator] Usage: send <pubkey> <type> <json>")
				continue
			}
			target := parts[1]
			msgType := parts[2]
			payloadRaw := strings.TrimSpace(strings.Join(parts[3:], " "))
			payload, err := parseJSONPayload(payloadRaw)
			if err != nil {
				fmt.Printf("[Operator] Invalid JSON payload: %v\n", err)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), operatorSendTimeout)
			resp, err := node.SendTyped(ctx, target, msgType, payload)
			cancel()
			if err != nil {
				fmt.Printf("[Operator] Send failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Send response from %s: %v\n", target, resp)
		case "block":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: block <pubkey>")
				continue
			}
			if err := node.BlockPeer(parts[1]); err != nil {
				fmt.Printf("[Operator] Block failed: %v\n", err)
				continue
			}
			fmt.Printf("[Operator] Blocked peer: %s\n", parts[1])
		case "unblock":
			if len(parts) < 2 {
				fmt.Println("[Operator] Usage: unblock <pubkey>")
				continue
			}
			if !node.UnblockPeer(parts[1]) {
				fmt.Printf("[Operator] Peer was not blocked: %s\n", parts[1])
				continue
			}
			fmt.Printf("[Operator] Unblocked peer: %s\n", parts[1])
		case "blocked":
			peers := node.BlockedPeers()
			if len(peers) == 0 {
				fmt.Println("[Operator] Blocklist is empty")
				continue
			}
			fmt.Printf("[Operator] Blocked peers (%d):\n", len(peers))
			for _, p := range peers {
				fmt.Printf("- %s\n", p)
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

func parseJSONPayload(raw string) (map[string]interface{}, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("payload cannot be empty")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, err
	}
	if decoded == nil {
		return nil, fmt.Errorf("payload must be a JSON object")
	}
	return decoded, nil
}

func isLikelyLoopbackAddr(addr string) bool {
	addr = strings.TrimSpace(strings.ToLower(addr))
	return strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "[::1]:")
}
