package agent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// MemoryChunk represents a unit of shared knowledge.
type MemoryChunk struct {
	Topic     string      `json:"topic"`
	Summary   string      `json:"summary"`
	Content   interface{} `json:"content"`
	Author    string      `json:"author"` // Eth Address or PeerID
	Timestamp int64       `json:"timestamp"`
	Price     float64     `json:"price"` // Cost in ETH
}

// MemoryStore handles local OpenClaw workspace monitoring and remote knowledge indexing.
type MemoryStore struct {
	db            *sql.DB
	workspacePath string // Path to OpenClaw memory directory
	mu            sync.RWMutex
}

type InboxEvent struct {
	EventID     string `json:"eventId"`
	RelayURL    string `json:"relayUrl"`
	Kind        int    `json:"kind"`
	Sender      string `json:"sender"`
	CreatedAt   int64  `json:"createdAt"`
	ReceivedAt  int64  `json:"receivedAt"`
	ProcessedAt int64  `json:"processedAt"`
	ProcessedBy string `json:"processedBy,omitempty"`
	Content     string `json:"content"`
	TagsJSON    string `json:"tagsJson"`
}

func NewMemoryStore(dbPath string, workspacePath string) (*MemoryStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables for REMOTE knowledge discovery
	schema := `
	CREATE TABLE IF NOT EXISTS remote_knowledge (
		topic_hash TEXT PRIMARY KEY,
		topic TEXT,
		summary TEXT,
		author TEXT,
		provider_id TEXT,
		price REAL,
		timestamp INTEGER
	);
	CREATE TABLE IF NOT EXISTS remote_tags (
		tag TEXT,
		topic_hash TEXT,
		FOREIGN KEY(topic_hash) REFERENCES remote_knowledge(topic_hash)
	);
	CREATE INDEX IF NOT EXISTS idx_remote_tags_tag ON remote_tags(tag);

	CREATE TABLE IF NOT EXISTS inbox_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id TEXT NOT NULL UNIQUE,
		relay_url TEXT,
		kind INTEGER NOT NULL,
		sender TEXT,
		created_at INTEGER NOT NULL,
		received_at INTEGER NOT NULL,
		processed_at INTEGER NOT NULL DEFAULT 0,
		processed_by TEXT,
		content TEXT,
		tags_json TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_inbox_events_received_at ON inbox_events(received_at DESC);
	CREATE INDEX IF NOT EXISTS idx_inbox_events_kind ON inbox_events(kind);
	CREATE INDEX IF NOT EXISTS idx_inbox_events_processed_at ON inbox_events(processed_at);

	CREATE TABLE IF NOT EXISTS relay_cursors (
		relay_url TEXT PRIMARY KEY,
		last_created_at INTEGER NOT NULL,
		last_event_id TEXT,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS mcp_default_rate (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		limit_count INTEGER NOT NULL,
		window_sec INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS mcp_tool_rates (
		tool TEXT PRIMARY KEY,
		limit_count INTEGER NOT NULL,
		window_sec INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS mcp_tool_acl (
		tool TEXT NOT NULL,
		pubkey TEXT NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (tool, pubkey)
	);

	CREATE TABLE IF NOT EXISTS mcp_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS blocked_peers (
		pubkey TEXT PRIMARY KEY,
		updated_at INTEGER NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}
	if _, err := db.Exec("ALTER TABLE inbox_events ADD COLUMN processed_at INTEGER NOT NULL DEFAULT 0"); err != nil && !isDuplicateColumnError(err) {
		return nil, fmt.Errorf("failed to migrate inbox_events.processed_at: %w", err)
	}
	if _, err := db.Exec("ALTER TABLE inbox_events ADD COLUMN processed_by TEXT"); err != nil && !isDuplicateColumnError(err) {
		return nil, fmt.Errorf("failed to migrate inbox_events.processed_by: %w", err)
	}

	return &MemoryStore{
		db:            db,
		workspacePath: workspacePath,
	}, nil
}

// SearchLocalWorkspace semantically searches the OpenClaw memory directory.
// For now, it performs a simple keyword/substring search on Markdown files.
func (s *MemoryStore) SearchLocalWorkspace(tag string) []MemoryChunk {
	if s.workspacePath == "" {
		return nil
	}

	var results []MemoryChunk
	files, _ := filepath.Glob(filepath.Join(s.workspacePath, "*.md"))

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		content := string(data)
		// Simulating semantic match via substring for demo
		if strings.Contains(strings.ToLower(content), strings.ToLower(tag)) {
			results = append(results, MemoryChunk{
				Topic:     filepath.Base(file),
				Summary:   fmt.Sprintf("Local match found in %s", filepath.Base(file)),
				Content:   content,
				Timestamp: time.Now().Unix(),
				Author:    "local-agent",
			})
		}
	}
	return results
}

// IndexRemoteKnowledge records knowledge available from other agents.
func (s *MemoryStore) IndexRemoteKnowledge(offer KnowledgeOffer, tags []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO remote_knowledge (topic_hash, topic, summary, author, provider_id, price, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		offer.TopicHash, offer.Topic, offer.Summary, offer.Author, offer.Provider, offer.Price, time.Now().Unix())
	if err != nil {
		tx.Rollback()
		return err
	}

	for _, tag := range tags {
		if _, err := tx.Exec("INSERT INTO remote_tags (tag, topic_hash) VALUES (?, ?)", tag, offer.TopicHash); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to insert tag %q: %w", tag, err)
		}
	}

	return tx.Commit()
}

// SearchRemoteIndex finds known remote knowledge providers.
func (s *MemoryStore) SearchRemoteIndex(tag string) ([]KnowledgeOffer, error) {
	rows, err := s.db.Query(`
		SELECT k.topic_hash, k.topic, k.summary, k.provider_id, k.price 
		FROM remote_knowledge k
		JOIN remote_tags t ON k.topic_hash = t.topic_hash
		WHERE t.tag = ?`, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []KnowledgeOffer
	for rows.Next() {
		var offer KnowledgeOffer
		if err := rows.Scan(&offer.TopicHash, &offer.Topic, &offer.Summary, &offer.Provider, &offer.Price); err == nil {
			results = append(results, offer)
		}
	}
	return results, nil
}

// Search returns summaries of memories matching a tag, prioritizes local OpenClaw files.
func (s *MemoryStore) Search(tag string) ([]MemoryChunk, error) {
	// 1. Search Local Workspace (OpenClaw)
	localMatches := s.SearchLocalWorkspace(tag)

	// 2. Search Remote Index (Metadata about others)
	remoteOffers, _ := s.SearchRemoteIndex(tag)

	// Convert remote offers to chunks for internal demo consistency
	for _, offer := range remoteOffers {
		localMatches = append(localMatches, MemoryChunk{
			Topic:     offer.Topic,
			Summary:   offer.Summary,
			Author:    offer.Author,
			Price:     offer.Price,
			Timestamp: time.Now().Unix(),
		})
	}

	return localMatches, nil
}

// GetMemory returns the contents of a local OpenClaw file by its "topic" (filename).
// This is used by the MemoryProtocol RPC handler.
func (s *MemoryStore) GetMemory(topic string) (*MemoryChunk, error) {
	if s.workspacePath == "" {
		return nil, nil
	}

	path := filepath.Join(s.workspacePath, topic)
	// Security check: ensure path is within workspace
	if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(s.workspacePath)) {
		return nil, fmt.Errorf("access denied")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	return &MemoryChunk{
		Topic:     topic,
		Content:   string(data),
		Summary:   "Retrieved from local OpenClaw workspace.",
		Timestamp: time.Now().Unix(),
		Author:    "local-agent",
	}, nil
}

func (s *MemoryStore) SaveInboxEvent(event InboxEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO inbox_events
		(event_id, relay_url, kind, sender, created_at, received_at, content, tags_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventID,
		event.RelayURL,
		event.Kind,
		event.Sender,
		event.CreatedAt,
		event.ReceivedAt,
		event.Content,
		event.TagsJSON,
	)
	return err
}

func (s *MemoryStore) ListInboxEvents(limit int) ([]InboxEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT event_id, relay_url, kind, sender, created_at, received_at, processed_at, COALESCE(processed_by, ''), content, tags_json
		FROM inbox_events
		ORDER BY received_at DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]InboxEvent, 0, limit)
	for rows.Next() {
		var ev InboxEvent
		if err := rows.Scan(
			&ev.EventID,
			&ev.RelayURL,
			&ev.Kind,
			&ev.Sender,
			&ev.CreatedAt,
			&ev.ReceivedAt,
			&ev.ProcessedAt,
			&ev.ProcessedBy,
			&ev.Content,
			&ev.TagsJSON,
		); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *MemoryStore) ListUnreadInboxEvents(limit int) ([]InboxEvent, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 500 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT event_id, relay_url, kind, sender, created_at, received_at, processed_at, COALESCE(processed_by, ''), content, tags_json
		FROM inbox_events
		WHERE processed_at = 0
		ORDER BY received_at ASC
		LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]InboxEvent, 0, limit)
	for rows.Next() {
		var ev InboxEvent
		if err := rows.Scan(
			&ev.EventID,
			&ev.RelayURL,
			&ev.Kind,
			&ev.Sender,
			&ev.CreatedAt,
			&ev.ReceivedAt,
			&ev.ProcessedAt,
			&ev.ProcessedBy,
			&ev.Content,
			&ev.TagsJSON,
		); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *MemoryStore) AckInboxEvent(eventID string, processedBy string) (bool, error) {
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return false, fmt.Errorf("event id cannot be empty")
	}
	processedBy = strings.TrimSpace(processedBy)
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`
		UPDATE inbox_events
		SET processed_at = ?, processed_by = ?
		WHERE event_id = ? AND processed_at = 0`,
		time.Now().UnixMilli(),
		processedBy,
		eventID,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (s *MemoryStore) GetRelayCursor(relayURL string) (int64, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ts int64
	var eventID string
	err := s.db.QueryRow(`
		SELECT last_created_at, COALESCE(last_event_id, '')
		FROM relay_cursors
		WHERE relay_url = ?`, relayURL).Scan(&ts, &eventID)
	if err == sql.ErrNoRows {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	return ts, eventID, nil
}

func (s *MemoryStore) SaveRelayCursor(relayURL string, lastCreatedAt int64, lastEventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO relay_cursors (relay_url, last_created_at, last_event_id, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(relay_url) DO UPDATE SET
			last_created_at = excluded.last_created_at,
			last_event_id = excluded.last_event_id,
			updated_at = excluded.updated_at`,
		relayURL, lastCreatedAt, lastEventID, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) SaveMCPDefaultRate(limit int, windowSec int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO mcp_default_rate (id, limit_count, window_sec, updated_at)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			limit_count = excluded.limit_count,
			window_sec = excluded.window_sec,
			updated_at = excluded.updated_at`,
		limit, windowSec, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) GetMCPDefaultRate() (int, int64, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var limit int
	var windowSec int64
	err := s.db.QueryRow(`
		SELECT limit_count, window_sec
		FROM mcp_default_rate
		WHERE id = 1`).Scan(&limit, &windowSec)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return limit, windowSec, true, nil
}

func (s *MemoryStore) SaveMCPToolRate(tool string, limit int, windowSec int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO mcp_tool_rates (tool, limit_count, window_sec, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(tool) DO UPDATE SET
			limit_count = excluded.limit_count,
			window_sec = excluded.window_sec,
			updated_at = excluded.updated_at`,
		tool, limit, windowSec, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) DeleteMCPToolRate(tool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM mcp_tool_rates WHERE tool = ?`, tool)
	return err
}

func (s *MemoryStore) ListMCPToolRates() ([]MCPRatePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT tool, limit_count, window_sec
		FROM mcp_tool_rates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MCPRatePolicy, 0)
	for rows.Next() {
		var p MCPRatePolicy
		if err := rows.Scan(&p.Tool, &p.Limit, &p.WindowSec); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *MemoryStore) SaveMCPToolACL(tool string, pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO mcp_tool_acl (tool, pubkey, updated_at)
		VALUES (?, ?, ?)`,
		tool, pubkey, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) DeleteMCPToolACL(tool string, pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM mcp_tool_acl WHERE tool = ? AND pubkey = ?`, tool, pubkey)
	return err
}

func (s *MemoryStore) DeleteAllMCPToolACL(tool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM mcp_tool_acl WHERE tool = ?`, tool)
	return err
}

func (s *MemoryStore) ListMCPToolACL() (map[string][]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT tool, pubkey
		FROM mcp_tool_acl`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]string)
	for rows.Next() {
		var tool string
		var pubkey string
		if err := rows.Scan(&tool, &pubkey); err != nil {
			return nil, err
		}
		out[tool] = append(out[tool], pubkey)
	}
	return out, nil
}

func (s *MemoryStore) SaveMCPACLDefaultDeny(defaultDeny bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value := "0"
	if defaultDeny {
		value = "1"
	}
	_, err := s.db.Exec(`
		INSERT INTO mcp_settings (key, value, updated_at)
		VALUES ('acl_default_deny', ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at`,
		value, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) GetMCPACLDefaultDeny() (bool, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var value string
	err := s.db.QueryRow(`
		SELECT value
		FROM mcp_settings
		WHERE key = 'acl_default_deny'`).Scan(&value)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return strings.TrimSpace(value) == "1", true, nil
}

func (s *MemoryStore) SaveBlockedPeer(pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO blocked_peers (pubkey, updated_at)
		VALUES (?, ?)`,
		pubkey, time.Now().UnixMilli(),
	)
	return err
}

func (s *MemoryStore) DeleteBlockedPeer(pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM blocked_peers WHERE pubkey = ?`, pubkey)
	return err
}

func (s *MemoryStore) ListBlockedPeers() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT pubkey FROM blocked_peers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Compress simulates context distillation (e.g., using an LLM).
// In a real implementation, this would call an LLM to summarize logs.
func Compress(topic string, rawData interface{}) string {
	return fmt.Sprintf("Distilled context for %s: %v", topic, rawData)
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}

// Close releases database resources used by the memory store.
func (s *MemoryStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// KnowledgeOffer represents an indexed remote capability/knowledge result.
type KnowledgeOffer struct {
	TopicHash string  `json:"topicHash"`
	Topic     string  `json:"topic"`
	Summary   string  `json:"summary"`
	Price     float64 `json:"price"`
	Provider  string  `json:"provider"`
	Author    string  `json:"author"`
}
