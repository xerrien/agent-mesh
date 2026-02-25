package agent

const (
	MessageTypePing           = "ping"
	MessageTypeMessage        = "message"
	MessageTypeTask           = "task"
	MessageTypeProviderLookup = "provider_lookup"
	MessageTypePeerExchange   = "peer_exchange"
	MessageTypeResponse       = "response"
)

type AgentCapability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AgentMessage struct {
	Type      string      `json:"type"` // "task", "response", "error"
	Payload   interface{} `json:"payload"`
	Sender    string      `json:"sender"`
	Timestamp int64       `json:"timestamp"`
}

type PeerHint struct {
	PubKey      string   `json:"pubkey"`
	Relays      []string `json:"relays,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	LastSeenAt  int64    `json:"lastSeenAt,omitempty"`
}

// SignedPacket contains a signed message for secure discovery.
// Data is stored as a JSON string to ensure deterministic signing.
type SignedPacket struct {
	Data      string `json:"data"`      // JSON-encoded payload (signed as-is)
	Signature string `json:"signature"` // Base64-encoded Ed25519 signature
	PeerID    string `json:"peerId"`
}
