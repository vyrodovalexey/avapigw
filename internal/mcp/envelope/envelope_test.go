package envelope

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testKey() []byte {
	k := make([]byte, KeySize)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func newSealer(t *testing.T) *AEADSealer {
	t.Helper()
	s, err := NewAEADSealer(testKey())
	require.NoError(t, err)
	return s
}

func digest(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

func sampleEnvelope() *Envelope {
	return &Envelope{
		UpstreamID:    "up1",
		Primitive:     "search",
		ParamDigest:   digest("q=hello"),
		Principal:     "user@example.com",
		IssuedAt:      time.Now(),
		TTL:           time.Minute,
		OperationID:   "op-123",
		UpstreamState: json.RawMessage(`{"cursor":"abc","state":42}`),
		RetriedMethod: "tools/call",
	}
}

func TestNewAEADSealer(t *testing.T) {
	t.Parallel()

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()
		s, err := NewAEADSealer(testKey())
		require.NoError(t, err)
		assert.NotNil(t, s)
	})

	t.Run("wrong key length", func(t *testing.T) {
		t.Parallel()
		_, err := NewAEADSealer([]byte("short"))
		require.ErrorIs(t, err, ErrInvalidKey)
	})
}

// UT-ENV-01: seal/open round-trip preserves upstream state verbatim.
func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	ctx := context.Background()

	e := sampleEnvelope()
	token, err := s.Seal(ctx, e)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	// Nonce populated during seal.
	assert.NotEmpty(t, e.Nonce)

	got, err := s.Open(ctx, token)
	require.NoError(t, err)

	assert.Equal(t, e.UpstreamID, got.UpstreamID)
	assert.Equal(t, e.Primitive, got.Primitive)
	assert.Equal(t, e.ParamDigest, got.ParamDigest)
	assert.Equal(t, e.Principal, got.Principal)
	assert.Equal(t, e.OperationID, got.OperationID)
	assert.Equal(t, e.RetriedMethod, got.RetriedMethod)
	// UpstreamState preserved verbatim (byte-for-byte JSON equality).
	assert.JSONEq(t, string(e.UpstreamState), string(got.UpstreamState))
	assert.Equal(t, e.Nonce, got.Nonce)
}

func TestSealPreservesProvidedNonce(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	e := sampleEnvelope()
	e.Nonce = []byte("fixed-nonce-value")

	token, err := s.Seal(context.Background(), e)
	require.NoError(t, err)
	got, err := s.Open(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, []byte("fixed-nonce-value"), got.Nonce)
}

func TestSealNilEnvelope(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	_, err := s.Seal(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil envelope")
}

func TestOpenErrors(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	ctx := context.Background()

	t.Run("invalid base64", func(t *testing.T) {
		t.Parallel()
		_, err := s.Open(ctx, "!!!not-base64!!!")
		require.ErrorIs(t, err, ErrIntegrity)
	})

	t.Run("too short", func(t *testing.T) {
		t.Parallel()
		short := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
		_, err := s.Open(ctx, short)
		require.ErrorIs(t, err, ErrIntegrity)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		t.Parallel()
		token, err := s.Seal(ctx, sampleEnvelope())
		require.NoError(t, err)
		raw, err := base64.RawURLEncoding.DecodeString(token)
		require.NoError(t, err)
		raw[len(raw)-1] ^= 0xFF // flip a ciphertext bit
		tampered := base64.RawURLEncoding.EncodeToString(raw)
		_, err = s.Open(ctx, tampered)
		require.ErrorIs(t, err, ErrIntegrity)
	})

	t.Run("cross-key rejected", func(t *testing.T) {
		t.Parallel()
		token, err := s.Seal(ctx, sampleEnvelope())
		require.NoError(t, err)
		other, err := NewAEADSealer(make([]byte, KeySize)) // different key (all zeros)
		require.NoError(t, err)
		_, err = other.Open(ctx, token)
		require.ErrorIs(t, err, ErrIntegrity)
	})
}

func TestOpenExpired(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	ctx := context.Background()

	e := sampleEnvelope()
	e.IssuedAt = time.Now().Add(-time.Hour)
	e.TTL = time.Minute // already elapsed

	token, err := s.Seal(ctx, e)
	require.NoError(t, err)
	_, err = s.Open(ctx, token)
	require.ErrorIs(t, err, ErrExpired)
}

func TestExpiredHelper(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)

	// TTL <= 0 never expires.
	e := &Envelope{IssuedAt: now, TTL: 0}
	assert.False(t, e.expired(now.Add(time.Hour)))
	e.TTL = -time.Second
	assert.False(t, e.expired(now.Add(time.Hour)))

	// Positive TTL.
	e.TTL = time.Minute
	assert.False(t, e.expired(now.Add(30*time.Second)))
	assert.True(t, e.expired(now.Add(2*time.Minute)))
	// Exactly at boundary is not yet expired (After is strict).
	assert.False(t, e.expired(now.Add(time.Minute)))
}

// UT-ENV-03: single-use nonce consumed once.
func TestConsume(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	ctx := context.Background()

	nonce := []byte("nonce-1")
	require.NoError(t, s.Consume(ctx, nonce))
	// Second consume of same nonce fails.
	err := s.Consume(ctx, nonce)
	require.ErrorIs(t, err, ErrConsumed)

	// A different nonce is fine.
	require.NoError(t, s.Consume(ctx, []byte("nonce-2")))

	// Empty nonce rejected.
	err = s.Consume(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty nonce")
}

// UT-ENV-02: VerifyRetry rejects tampered/expired/cross-principal/cross-params.
func TestVerifyRetry(t *testing.T) {
	t.Parallel()

	base := func() *Envelope {
		return &Envelope{
			Principal:     "user@example.com",
			RetriedMethod: "tools/call",
			ParamDigest:   digest("q=hello"),
			IssuedAt:      time.Now(),
			TTL:           time.Minute,
		}
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		err := VerifyRetry(base(), "user@example.com", "tools/call", digest("q=hello"))
		require.NoError(t, err)
	})

	t.Run("nil envelope", func(t *testing.T) {
		t.Parallel()
		err := VerifyRetry(nil, "u", "m", nil)
		require.ErrorIs(t, err, ErrIntegrity)
	})

	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		e := base()
		e.IssuedAt = time.Now().Add(-time.Hour)
		err := VerifyRetry(e, "user@example.com", "tools/call", digest("q=hello"))
		require.ErrorIs(t, err, ErrExpired)
	})

	t.Run("cross-principal", func(t *testing.T) {
		t.Parallel()
		err := VerifyRetry(base(), "attacker@example.com", "tools/call", digest("q=hello"))
		require.ErrorIs(t, err, ErrPrincipalMismatch)
	})

	t.Run("cross-method", func(t *testing.T) {
		t.Parallel()
		err := VerifyRetry(base(), "user@example.com", "resources/read", digest("q=hello"))
		require.ErrorIs(t, err, ErrMethodMismatch)
	})

	t.Run("cross-params", func(t *testing.T) {
		t.Parallel()
		err := VerifyRetry(base(), "user@example.com", "tools/call", digest("q=different"))
		require.ErrorIs(t, err, ErrParamMismatch)
	})
}

// End-to-end: seal, open, verify, consume — the full MRTR retry path.
func TestSealOpenVerifyConsumeFlow(t *testing.T) {
	t.Parallel()
	s := newSealer(t)
	ctx := context.Background()

	e := sampleEnvelope()
	token, err := s.Seal(ctx, e)
	require.NoError(t, err)

	opened, err := s.Open(ctx, token)
	require.NoError(t, err)

	require.NoError(t, VerifyRetry(opened, e.Principal, e.RetriedMethod, e.ParamDigest))
	require.NoError(t, s.Consume(ctx, opened.Nonce))
	// Replay of the same token: open+verify succeed but consume fails (single use).
	require.ErrorIs(t, s.Consume(ctx, opened.Nonce), ErrConsumed)
}
