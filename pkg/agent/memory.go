package agent

import (
	"database/sql"
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
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
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

// Compress simulates context distillation (e.g., using an LLM).
// In a real implementation, this would call an LLM to summarize logs.
func Compress(topic string, rawData interface{}) string {
	return fmt.Sprintf("Distilled context for %s: %v", topic, rawData)
}

// KnowledgeDiscoveryMsg is sent over Gossipsub to find flexible memory.
type KnowledgeDiscoveryMsg struct {
	Query     string   `json:"query"`     // Natural language intent
	Tags      []string `json:"tags"`      // Optional structured filters
	Requester string   `json:"requester"` // PeerID
	Timestamp int64    `json:"timestamp"`
}

// KnowledgeOffer is a response to a discovery message.
type KnowledgeOffer struct {
	TopicHash string  `json:"topicHash"`
	Topic     string  `json:"topic"`
	Summary   string  `json:"summary"`
	Price     float64 `json:"price"`
	Provider  string  `json:"provider"`
	Author    string  `json:"author"`
}
