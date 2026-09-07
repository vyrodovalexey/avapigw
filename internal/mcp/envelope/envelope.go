// Package envelope implements the AEAD-protected MRTR envelope that wraps an
// upstream requestState (HUB-202..204, 207, 209). The hub seals upstream state
// together with routing/authorization context (upstream id, de-namespaced
// primitive, parameter digest, principal, issue time and TTL) so that any
// replica can unwrap, verify and route a retry without shared session state,
// and so tampered, expired, cross-principal or cross-request retries are
// rejected.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// KeySize is the required AEAD key length in bytes (AES-256-GCM).
const KeySize = 32

// Sentinel errors returned by Open / VerifyRetry / Consume.
var (
	// ErrInvalidKey indicates a key of the wrong length was supplied.
	ErrInvalidKey = errors.New("envelope: key must be 32 bytes")
	// ErrIntegrity indicates the token failed AEAD verification.
	ErrIntegrity = errors.New("envelope: integrity verification failed")
	// ErrExpired indicates the envelope TTL has elapsed.
	ErrExpired = errors.New("envelope: expired")
	// ErrPrincipalMismatch indicates the retry principal differs from the
	// sealed principal.
	ErrPrincipalMismatch = errors.New("envelope: principal mismatch")
	// ErrMethodMismatch indicates the retry method differs from the sealed
	// method.
	ErrMethodMismatch = errors.New("envelope: method mismatch")
	// ErrParamMismatch indicates the retry parameter digest differs from the
	// sealed digest.
	ErrParamMismatch = errors.New("envelope: parameter digest mismatch")
	// ErrConsumed indicates a single-use nonce has already been consumed.
	ErrConsumed = errors.New("envelope: nonce already consumed")
)

// Envelope carries the sealed MRTR state and its verification context.
type Envelope struct {
	// UpstreamID identifies the upstream that issued the state.
	UpstreamID string `json:"upstreamId"`
	// Primitive is the de-namespaced primitive name.
	Primitive string `json:"primitive"`
	// ParamDigest is a digest of the salient request parameters.
	ParamDigest []byte `json:"paramDigest"`
	// Principal is the authenticated principal that owns the operation.
	Principal string `json:"principal"`
	// IssuedAt is the envelope issue timestamp.
	IssuedAt time.Time `json:"issuedAt"`
	// TTL bounds the envelope's validity window.
	TTL time.Duration `json:"ttl"`
	// OperationID links MRTR rounds and spans across the operation.
	OperationID string `json:"operationId"`
	// UpstreamState is the original upstream requestState, forwarded
	// verbatim on retry (HUB-202).
	UpstreamState json.RawMessage `json:"upstreamState,omitempty"`
	// Nonce provides single-use enforcement (HUB-209).
	Nonce []byte `json:"nonce"`
	// RetriedMethod records the method the envelope was issued for so retries
	// can be matched (HUB-203).
	RetriedMethod string `json:"retriedMethod"`
	// Round is the server-sealed 1-based round number this envelope was
	// issued for. It is authoritative: the next retry is Round+1, so a
	// client cannot forge the round counter (HUB-208).
	Round int `json:"round"`
	// OperationStart is the sealed wall-clock start of the logical MRTR
	// operation, used to enforce the total budget across rounds (HUB-208).
	OperationStart time.Time `json:"operationStart"`
}

// expired reports whether the envelope is past its TTL relative to now.
func (e *Envelope) expired(now time.Time) bool {
	if e.TTL <= 0 {
		return false
	}
	return now.After(e.IssuedAt.Add(e.TTL))
}

// Sealer seals and opens MRTR envelopes and enforces single-use nonces.
type Sealer interface {
	// Seal encrypts the envelope and returns an opaque token.
	Seal(ctx context.Context, e *Envelope) (token string, err error)
	// Open decrypts and integrity-verifies a token, returning the envelope.
	Open(ctx context.Context, token string) (*Envelope, error)
	// Consume marks a nonce used, returning ErrConsumed on reuse (HUB-209).
	Consume(ctx context.Context, nonce []byte) error
}

// NonceStore records single-use MRTR nonces so a retry can be honored exactly
// once (HUB-207/209/501). Consume atomically records the nonce and returns
// ErrConsumed when the nonce was already recorded, so any replica that shares
// the store rejects a replayed retry. ttl bounds how long the record is
// retained (the envelope TTL): after it elapses the nonce may be reused only
// because the envelope itself is expired and rejected by Open first.
type NonceStore interface {
	// Consume records nonce as used, returning ErrConsumed on reuse. The
	// check-and-record MUST be atomic (no time-of-check/time-of-use window,
	// HUB-209).
	Consume(ctx context.Context, nonce []byte, ttl time.Duration) error
}

// AEADSealer is the default in-process Sealer using AES-256-GCM. The token is
// base64url(nonce || ciphertext). Single-use enforcement is delegated to a
// pluggable NonceStore (HUB-207): the default is a bounded in-memory store with
// TTL eviction; a Redis-backed store makes single-use cross-replica.
type AEADSealer struct {
	aead   cipher.AEAD
	nonces NonceStore
	ttl    time.Duration
}

// SealerOption configures an AEADSealer.
type SealerOption func(*AEADSealer)

// WithNonceStore injects the single-use NonceStore (HUB-207). When unset the
// sealer uses a bounded in-memory store with TTL eviction.
func WithNonceStore(store NonceStore) SealerOption {
	return func(s *AEADSealer) {
		if store != nil {
			s.nonces = store
		}
	}
}

// WithConsumeTTL sets the TTL passed to the NonceStore on Consume so records
// are retained at least as long as an envelope can be replayed (HUB-207/209).
// Non-positive values are ignored.
func WithConsumeTTL(ttl time.Duration) SealerOption {
	return func(s *AEADSealer) {
		if ttl > 0 {
			s.ttl = ttl
		}
	}
}

// DefaultNonceTTL is the fallback single-use retention window when no TTL is
// configured. It mirrors the default envelope TTL so a nonce cannot outlive
// the token that could replay it.
const DefaultNonceTTL = 5 * time.Minute

// NewAEADSealer constructs an AEADSealer from a 32-byte key.
func NewAEADSealer(key []byte, opts ...SealerOption) (*AEADSealer, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: new gcm: %w", err)
	}
	s := &AEADSealer{
		aead: aead,
		ttl:  DefaultNonceTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.nonces == nil {
		s.nonces = NewMemoryNonceStore()
	}
	return s, nil
}

// Seal encrypts the envelope. When the envelope has no Nonce a fresh random
// nonce is generated so every sealed envelope is single-use-addressable.
func (s *AEADSealer) Seal(_ context.Context, e *Envelope) (string, error) {
	if e == nil {
		return "", errors.New("envelope: nil envelope")
	}
	if len(e.Nonce) == 0 {
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", fmt.Errorf("envelope: generate nonce: %w", err)
		}
		e.Nonce = nonce
	}

	plaintext, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("envelope: marshal: %w", err)
	}

	gcmNonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(gcmNonce); err != nil {
		return "", fmt.Errorf("envelope: generate gcm nonce: %w", err)
	}
	ciphertext := s.aead.Seal(nil, gcmNonce, plaintext, nil)

	token := make([]byte, 0, len(gcmNonce)+len(ciphertext))
	token = append(token, gcmNonce...)
	token = append(token, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Open decrypts and verifies a token (HUB-203 integrity + expiry). It does not
// consume the nonce; callers enforce single-use via Consume.
func (s *AEADSealer) Open(_ context.Context, token string) (*Envelope, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return nil, ErrIntegrity
	}
	gcmNonce, ciphertext := raw[:ns], raw[ns:]

	plaintext, err := s.aead.Open(nil, gcmNonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
	}

	var e Envelope
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return nil, fmt.Errorf("envelope: unmarshal: %w", err)
	}
	if e.expired(time.Now()) {
		return nil, ErrExpired
	}
	return &e, nil
}

// Consume marks a nonce as used, returning ErrConsumed on reuse (HUB-209). It
// delegates to the configured NonceStore so single-use is enforced across
// replicas when a shared (e.g. Redis) store is injected (HUB-207/501).
func (s *AEADSealer) Consume(ctx context.Context, nonce []byte) error {
	if len(nonce) == 0 {
		return errors.New("envelope: empty nonce")
	}
	return s.nonces.Consume(ctx, nonce, s.ttl)
}

// VerifyRetry verifies that an opened envelope matches the presented retry
// context (HUB-203): same principal, same method and same parameter digest,
// and that it has not expired. The parameter digest is compared in constant
// time. It does not enforce single-use; call Sealer.Consume for that.
func VerifyRetry(e *Envelope, principal, method string, paramDigest []byte) error {
	if e == nil {
		return ErrIntegrity
	}
	if e.expired(time.Now()) {
		return ErrExpired
	}
	if subtle.ConstantTimeCompare([]byte(e.Principal), []byte(principal)) != 1 {
		return ErrPrincipalMismatch
	}
	if e.RetriedMethod != method {
		return ErrMethodMismatch
	}
	if subtle.ConstantTimeCompare(e.ParamDigest, paramDigest) != 1 {
		return ErrParamMismatch
	}
	return nil
}
