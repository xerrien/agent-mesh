package agent

import (
	"fmt"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip44"
)

func normalizePubKey(raw string) (string, error) {
	pk, err := nostr.PubKeyFromHex(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("target must be nostr pubkey hex: %w", err)
	}
	return pk.Hex(), nil
}

func extractMessageText(payload interface{}) (string, bool) {
	switch v := payload.(type) {
	case string:
		s := strings.TrimSpace(v)
		return s, s != ""
	case map[string]interface{}:
		raw, ok := v["text"]
		if !ok {
			return "", false
		}
		txt, ok := raw.(string)
		if !ok {
			return "", false
		}
		txt = strings.TrimSpace(txt)
		return txt, txt != ""
	default:
		return "", false
	}
}

func (n *AgentNode) extractMessageTextForSender(sender string, payload interface{}) (string, bool) {
	if text, ok := extractMessageText(payload); ok {
		return text, true
	}
	ciphertext, ok := extractEncryptedMessagePayload(payload)
	if !ok {
		return "", false
	}
	plaintext, err := n.decryptFromPeer(sender, ciphertext)
	if err != nil {
		return "", false
	}
	plaintext = strings.TrimSpace(plaintext)
	return plaintext, plaintext != ""
}

func extractEncryptedMessagePayload(payload interface{}) (string, bool) {
	m, ok := payload.(map[string]interface{})
	if !ok {
		return "", false
	}
	rawEncoding, ok := m["encoding"]
	if !ok {
		return "", false
	}
	encoding, ok := rawEncoding.(string)
	if !ok || strings.TrimSpace(strings.ToLower(encoding)) != directMsgEncodingNIP44 {
		return "", false
	}
	rawCipher, ok := m["ciphertext"]
	if !ok {
		return "", false
	}
	ciphertext, ok := rawCipher.(string)
	if !ok {
		return "", false
	}
	ciphertext = strings.TrimSpace(ciphertext)
	return ciphertext, ciphertext != ""
}

func (n *AgentNode) encryptForPeer(peerID string, plaintext string) (string, error) {
	pk, err := nostr.PubKeyFromHex(peerID)
	if err != nil {
		return "", err
	}
	n.mu.RLock()
	sk := n.secretKey
	n.mu.RUnlock()
	ck, err := nip44.GenerateConversationKey(pk, sk)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(plaintext, ck)
}

func (n *AgentNode) decryptFromPeer(peerID string, ciphertext string) (string, error) {
	pk, err := nostr.PubKeyFromHex(peerID)
	if err != nil {
		return "", err
	}
	n.mu.RLock()
	sk := n.secretKey
	n.mu.RUnlock()
	ck, err := nip44.GenerateConversationKey(pk, sk)
	if err != nil {
		return "", err
	}
	return nip44.Decrypt(ciphertext, ck)
}
