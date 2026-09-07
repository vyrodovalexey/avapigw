// Package security implements the MCP hub's security-hardening building blocks
// (HUB-401..408): the shared AEAD key loader for stateless multi-replica
// operation (HUB-166/207), log/argument redaction (HUB-407), icon-URI
// validation (HUB-406), bounded schema validation (HUB-403/404) and
// tool-definition drift detection (HUB-402).
package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// defaultKVField is the default KV field holding the base64 shared key.
const defaultKVField = "key"

// transitDeriveInput is the fixed plaintext encrypted via Vault Transit to
// derive a stable, cluster-wide 32-byte key. Every replica sharing the same
// Transit key produces the same digest, so the derived AEAD key is identical
// across replicas without exposing the Transit key material itself.
const transitDeriveInput = "avapigw-mcp-shared-key-v1"

// ErrNoSharedKey indicates no shared-key source was configured.
var ErrNoSharedKey = errors.New("security: no shared key source configured")

// LoadSharedKey resolves the shared AEAD key from the configured source
// (HUB-166/207). It returns a 32-byte key suitable for envelope.NewAEADSealer.
// When cfg is nil ErrNoSharedKey is returned so the caller can fall back to a
// generated key with a WARN (single-replica dev).
func LoadSharedKey(ctx context.Context, cfg *config.MCPSharedKey, vc vault.Client) ([]byte, error) {
	if cfg == nil || cfg.Source == "" {
		return nil, ErrNoSharedKey
	}
	switch cfg.Source {
	case config.MCPKeySourceInline:
		return decodeInlineKey(cfg.Value)
	case config.MCPKeySourceVaultKV:
		return loadKVKey(ctx, cfg, vc)
	case config.MCPKeySourceVaultTransit:
		return deriveTransitKey(ctx, cfg, vc)
	default:
		return nil, fmt.Errorf("security: unknown shared key source %q", cfg.Source)
	}
}

// GenerateKey returns a fresh random 32-byte AEAD key for the single-replica
// fallback path.
func GenerateKey() ([]byte, error) {
	key := make([]byte, envelope.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("security: generate key: %w", err)
	}
	return key, nil
}

// decodeInlineKey decodes a base64 (standard or raw-url) 32-byte key.
func decodeInlineKey(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("security: inline shared key is empty")
	}
	key, err := decodeBase64(value)
	if err != nil {
		return nil, fmt.Errorf("security: decode inline key: %w", err)
	}
	if len(key) != envelope.KeySize {
		return nil, fmt.Errorf("security: inline key must be %d bytes, got %d", envelope.KeySize, len(key))
	}
	return key, nil
}

// loadKVKey reads a base64 key from a Vault KV secret field (HUB-207).
func loadKVKey(ctx context.Context, cfg *config.MCPSharedKey, vc vault.Client) ([]byte, error) {
	if vc == nil || !vc.IsEnabled() {
		return nil, errors.New("security: vault client unavailable for shared key")
	}
	if cfg.VaultMount == "" || cfg.VaultPath == "" {
		return nil, errors.New("security: vaultKV shared key requires vaultMount and vaultPath")
	}
	field := cfg.VaultField
	if field == "" {
		field = defaultKVField
	}
	data, err := vc.KV().Read(ctx, cfg.VaultMount, cfg.VaultPath)
	if err != nil {
		return nil, fmt.Errorf("security: read shared key from vault: %w", err)
	}
	raw, ok := data[field]
	if !ok {
		return nil, fmt.Errorf("security: shared key field %q not found in vault secret", field)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("security: shared key field %q is not a string", field)
	}
	return decodeInlineKey(s)
}

// deriveTransitKey derives a stable 32-byte key from a Vault Transit key
// (HUB-207). The fixed input yields a deterministic ciphertext-independent key
// via SHA-256 over the Transit ciphertext; because Transit ciphertext is not
// deterministic, we instead sign the fixed input which IS deterministic for a
// non-rotated key. Sign is used to keep the derivation reproducible across
// replicas.
func deriveTransitKey(ctx context.Context, cfg *config.MCPSharedKey, vc vault.Client) ([]byte, error) {
	if vc == nil || !vc.IsEnabled() {
		return nil, errors.New("security: vault client unavailable for shared key")
	}
	if cfg.VaultMount == "" || cfg.VaultPath == "" {
		return nil, errors.New("security: vaultTransit shared key requires vaultMount and vaultPath")
	}
	sig, err := vc.Transit().Sign(ctx, cfg.VaultMount, cfg.VaultPath, []byte(transitDeriveInput))
	if err != nil {
		return nil, fmt.Errorf("security: derive shared key via transit: %w", err)
	}
	// Fold the signature into a fixed 32-byte key. The signature is stable
	// for a fixed input and a non-rotated key, so every replica derives the
	// same key.
	sum := sha256.Sum256(sig)
	return sum[:], nil
}

// decodeBase64 tries standard then raw-url base64 decoding.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
