package agent

const (
	MessageTypePing           = "ping"
	MessageTypeMessage        = "message"
	MessageTypeResponse       = "response"
)

const (
	SchemaPingV1           = "agentswarm.ping.v1"
	SchemaMessageV1        = "agentswarm.message.v1"
	SchemaResponseV1       = "agentswarm.response.v1"
)

const (
	ReceiptStageAccepted  = "accepted"
	ReceiptStageProcessed = "processed"
	ReceiptStageFailed    = "failed"
)

type AgentCapability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	MCP         *MCPDescriptor `json:"mcp,omitempty"`
}

type MCPToolInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type MCPDescriptor struct {
	Endpoint   string        `json:"endpoint,omitempty"`
	SchemaHash string        `json:"schemaHash,omitempty"`
	Tools      []MCPToolInfo `json:"tools,omitempty"`
}

type MessageMeta struct {
	ID          string `json:"id,omitempty"`
	ReplyTo     string `json:"replyTo,omitempty"`
	Schema      string `json:"schema,omitempty"`
	Purpose     string `json:"purpose,omitempty"`
	TimeoutMs   int64  `json:"timeoutMs,omitempty"`
	DeadlineMs  int64  `json:"deadlineMs,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	RequiresAck bool   `json:"requiresAck,omitempty"`
}

type MessageReceipt struct {
	Stage   string `json:"stage"`
	Code    string `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
	At      int64  `json:"at"`
	ReplyTo string `json:"replyTo,omitempty"`
}

type AgentMessage struct {
	Type      string       `json:"type"` // "task", "response", "error"
	Payload   interface{}  `json:"payload"`
	Sender    string       `json:"sender"`
	Timestamp int64        `json:"timestamp"`
	Meta      *MessageMeta `json:"meta,omitempty"`
}

// SignedPacket contains a signed message for secure discovery.
// Data is stored as a JSON string to ensure deterministic signing.
type SignedPacket struct {
	Data      string `json:"data"`      // JSON-encoded payload (signed as-is)
	Signature string `json:"signature"` // Base64-encoded Ed25519 signature
	PeerID    string `json:"peerId"`
}





