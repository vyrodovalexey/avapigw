package apikey

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Store type constants.
const (
	storeTypeMemory = "memory"
	storeTypeFile   = "file"
	storeTypeVault  = "vault"
)

// Config represents API Key authentication configuration.
type Config struct {
	// Enabled enables API Key authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// HashAlgorithm is the algorithm used to hash API keys.
	// Supported: sha256, sha512, bcrypt, plaintext (dev only).
	// Note: bcrypt is not supported with the vault store (see Validate).
	HashAlgorithm string `yaml:"hashAlgorithm,omitempty" json:"hashAlgorithm,omitempty"`

	// Store configures the API key store.
	Store *StoreConfig `yaml:"store,omitempty" json:"store,omitempty"`

	// Extraction configures how API keys are extracted from requests.
	Extraction []ExtractionSource `yaml:"extraction,omitempty" json:"extraction,omitempty"`

	// RateLimit configures per-key rate limiting.
	RateLimit *RateLimitConfig `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"`

	// Cache configures API key caching.
	Cache *CacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// Vault configures Vault integration.
	Vault *VaultConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// ExtractionSource represents a source for API key extraction.
type ExtractionSource struct {
	// Type is the extraction type (header, query, metadata).
	Type string `yaml:"type" json:"type"`

	// Name is the name of the header, query parameter, or metadata key.
	Name string `yaml:"name" json:"name"`

	// Prefix is the prefix to strip from the value.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
}

// StoreConfig configures the API key store.
type StoreConfig struct {
	// Type is the store type (memory, vault, file).
	Type string `yaml:"type" json:"type"`

	// FilePath is the path to the API keys file (for file store).
	FilePath string `yaml:"filePath,omitempty" json:"filePath,omitempty"`

	// Keys is a list of static API keys (for memory store).
	Keys []StaticKey `yaml:"keys,omitempty" json:"keys,omitempty"`
}

// StaticKey represents a static API key configuration.
type StaticKey struct {
	// ID is the unique identifier for the key.
	ID string `yaml:"id" json:"id"`

	// Key is the raw API key value. Optional when Hash is set: hash-only
	// entries are supported for sha256, sha512 and bcrypt algorithms.
	Key string `yaml:"key" json:"key"`

	// Hash is the pre-computed hash of the key using the configured
	// hashAlgorithm (hex-encoded digest for sha256/sha512, bcrypt string
	// for bcrypt). Required when Key is empty.
	Hash string `yaml:"hash,omitempty" json:"hash,omitempty"`

	// Name is a human-readable name for the key.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	// Scopes is a list of scopes granted to the key.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// Roles is a list of roles granted to the key.
	Roles []string `yaml:"roles,omitempty" json:"roles,omitempty"`

	// ExpiresAt is when the key expires.
	ExpiresAt *time.Time `yaml:"expiresAt,omitempty" json:"expiresAt,omitempty"`

	// Metadata contains additional metadata.
	Metadata map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`

	// Enabled indicates if the key is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// RateLimitConfig configures per-key rate limiting.
type RateLimitConfig struct {
	// Enabled enables rate limiting.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RequestsPerSecond is the default rate limit.
	RequestsPerSecond int `yaml:"requestsPerSecond,omitempty" json:"requestsPerSecond,omitempty"`

	// Burst is the burst size.
	Burst int `yaml:"burst,omitempty" json:"burst,omitempty"`
}

// CacheConfig configures API key caching.
type CacheConfig struct {
	// Enabled enables caching.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// TTL is the cache TTL.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxSize is the maximum number of entries (enforced with LRU
	// eviction). A value <= 0 disables the bound.
	MaxSize int `yaml:"maxSize,omitempty" json:"maxSize,omitempty"`
}

// VaultConfig configures Vault integration for API keys.
type VaultConfig struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// KVMount is the Vault KV mount path.
	KVMount string `yaml:"kvMount,omitempty" json:"kvMount,omitempty"`

	// Path is the path prefix for API keys in Vault.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
}

// Validate validates the API Key configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if err := c.validateHashAlgorithm(); err != nil {
		return err
	}
	if err := c.validateStore(); err != nil {
		return err
	}
	if err := c.validateStaticKeys(); err != nil {
		return err
	}
	if err := c.validateExtraction(); err != nil {
		return err
	}
	if err := c.validateVault(); err != nil {
		return err
	}
	return c.validateCache()
}

// validateHashAlgorithm validates the hash algorithm configuration.
func (c *Config) validateHashAlgorithm() error {
	if c.HashAlgorithm == "" {
		return nil
	}
	validAlgorithms := map[string]bool{
		HashAlgSHA256:    true,
		HashAlgSHA512:    true,
		HashAlgBcrypt:    true,
		HashAlgPlaintext: true,
	}
	if !validAlgorithms[c.HashAlgorithm] {
		return fmt.Errorf("invalid hash algorithm: %s", c.HashAlgorithm)
	}
	return nil
}

// validateStore validates the store configuration.
func (c *Config) validateStore() error {
	if c.Store == nil {
		return nil
	}
	if err := c.Store.Validate(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// validateStaticKeys rejects static key entries that could never
// authenticate: an entry needs either a raw key value or a pre-computed
// hash compatible with the effective hash algorithm. Previously such
// entries were accepted at load time and silently failed every lookup.
func (c *Config) validateStaticKeys() error {
	if c.Store == nil {
		return nil
	}
	algorithm := c.GetEffectiveHashAlgorithm()
	for i := range c.Store.Keys {
		key := &c.Store.Keys[i]
		if key.Key != "" {
			continue
		}
		if key.Hash == "" {
			return fmt.Errorf("store.keys[%d] (id=%q): either key or hash must be set", i, key.ID)
		}
		if !isAlgorithmCompatibleHash(key.Hash, algorithm) {
			return fmt.Errorf("store.keys[%d] (id=%q): hash is not compatible with hash algorithm %q",
				i, key.ID, algorithm)
		}
	}
	return nil
}

// validateExtraction validates the extraction configuration.
func (c *Config) validateExtraction() error {
	for i, src := range c.Extraction {
		if err := validateExtractionSource(src); err != nil {
			return fmt.Errorf("extraction[%d]: %w", i, err)
		}
	}
	return nil
}

// validateVault validates the Vault configuration and its compatibility
// with the hash algorithm.
//
// Strategy note (addressing design): the Vault store addresses secrets by
// the deterministic digest of the raw key. bcrypt embeds a random salt, so
// the hash of a presented key can never be recomputed to derive the storage
// path — every lookup would silently miss. bcrypt is therefore rejected for
// Vault-backed storage at load time; use sha256 or sha512 instead.
func (c *Config) validateVault() error {
	if !c.usesVaultStore() {
		return nil
	}
	if c.GetEffectiveHashAlgorithm() == HashAlgBcrypt {
		return errors.New(`hashAlgorithm "bcrypt" is not supported with the vault store: ` +
			"bcrypt hashes are salted and cannot address vault paths (use sha256 or sha512)")
	}
	if c.Vault != nil && c.Vault.Enabled {
		if err := c.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}
	return nil
}

// usesVaultStore reports whether this configuration selects Vault-backed
// key storage, either via store.type or via an enabled vault section.
func (c *Config) usesVaultStore() bool {
	if c.Store != nil && c.Store.Type == storeTypeVault {
		return true
	}
	return c.Vault != nil && c.Vault.Enabled
}

// validateCache validates the cache configuration.
func (c *Config) validateCache() error {
	if c.Cache == nil || !c.Cache.Enabled {
		return nil
	}
	if c.Cache.TTL < 0 {
		return errors.New("cache.ttl must be non-negative")
	}
	if c.Cache.MaxSize < 0 {
		return errors.New("cache.maxSize must be non-negative")
	}
	return nil
}

// Validate validates the store configuration.
func (c *StoreConfig) Validate() error {
	if c == nil {
		return nil
	}

	validTypes := map[string]bool{
		"":              true,
		storeTypeMemory: true,
		storeTypeVault:  true,
		storeTypeFile:   true,
	}
	if !validTypes[c.Type] {
		return fmt.Errorf("invalid store type: %s", c.Type)
	}

	if c.Type == storeTypeFile && c.FilePath == "" {
		return errors.New("filePath is required for file store")
	}

	return nil
}

// Validate validates the Vault configuration.
func (c *VaultConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.KVMount == "" {
		return errors.New("kvMount is required")
	}

	return nil
}

// validateExtractionSource validates an extraction source.
func validateExtractionSource(src ExtractionSource) error {
	validTypes := map[string]bool{
		"header":   true,
		"query":    true,
		"metadata": true,
	}
	if !validTypes[src.Type] {
		return fmt.Errorf("invalid extraction type: %s", src.Type)
	}
	if src.Name == "" {
		return errors.New("name is required")
	}
	return nil
}

// isAlgorithmCompatibleHash reports whether a pre-computed hash can ever
// match a presented key under the given algorithm. Incompatible hashes make
// an entry silently unusable, so they are rejected at validation time.
func isAlgorithmCompatibleHash(hash, algorithm string) bool {
	switch algorithm {
	case HashAlgSHA256:
		return isHexDigest(hash, sha256.Size)
	case HashAlgSHA512:
		return isHexDigest(hash, sha512.Size)
	case HashAlgBcrypt:
		_, err := bcrypt.Cost([]byte(hash))
		return err == nil
	default:
		// plaintext (and unknown algorithms) compare against the raw key,
		// so a pre-computed hash alone is never usable.
		return false
	}
}

// isHexDigest reports whether hash is a valid hex encoding of a digest with
// the given byte size.
func isHexDigest(hash string, size int) bool {
	if len(hash) != size*2 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// normalizeHexDigest lower-cases a hex-encoded digest so configured hashes
// compare and index consistently with computed digests.
func normalizeHexDigest(hash string) string {
	return strings.ToLower(hash)
}

// DefaultConfig returns a default API Key configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:       false,
		HashAlgorithm: HashAlgSHA256,
		Extraction: []ExtractionSource{
			{
				Type: "header",
				Name: "X-API-Key",
			},
		},
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 10000,
		},
	}
}

// GetEffectiveHashAlgorithm returns the effective hash algorithm.
func (c *Config) GetEffectiveHashAlgorithm() string {
	if c.HashAlgorithm != "" {
		return c.HashAlgorithm
	}
	return HashAlgSHA256
}
