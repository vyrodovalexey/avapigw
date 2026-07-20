package httputil

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errReader always fails, simulating a broken connection mid-body.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestReadAllLimited(t *testing.T) {
	t.Parallel()

	t.Run("body under limit", func(t *testing.T) {
		t.Parallel()
		body, err := ReadAllLimited(strings.NewReader("hello"), 10)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(body))
	})

	t.Run("body exactly at limit", func(t *testing.T) {
		t.Parallel()
		body, err := ReadAllLimited(strings.NewReader("12345"), 5)
		require.NoError(t, err)
		assert.Equal(t, "12345", string(body))
	})

	t.Run("body over limit rejected", func(t *testing.T) {
		t.Parallel()
		_, err := ReadAllLimited(strings.NewReader("123456"), 5)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrResponseTooLarge)
		assert.Contains(t, err.Error(), "limit 5 bytes")
	})

	t.Run("non-positive limit uses default", func(t *testing.T) {
		t.Parallel()
		body, err := ReadAllLimited(strings.NewReader("payload"), 0)
		require.NoError(t, err)
		assert.Equal(t, "payload", string(body))
	})

	t.Run("read error propagated", func(t *testing.T) {
		t.Parallel()
		_, err := ReadAllLimited(errReader{}, 10)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrResponseTooLarge)
	})

	t.Run("empty body", func(t *testing.T) {
		t.Parallel()
		body, err := ReadAllLimited(strings.NewReader(""), 10)
		require.NoError(t, err)
		assert.Empty(t, body)
	})
}

func TestReadAllTruncated(t *testing.T) {
	t.Parallel()

	t.Run("body under limit unchanged", func(t *testing.T) {
		t.Parallel()
		body := ReadAllTruncated(strings.NewReader("small"), 10)
		assert.Equal(t, "small", string(body))
	})

	t.Run("body over limit truncated with marker", func(t *testing.T) {
		t.Parallel()
		body := ReadAllTruncated(strings.NewReader(strings.Repeat("x", 100)), 10)
		assert.Equal(t, strings.Repeat("x", 10)+"...(truncated)", string(body))
	})

	t.Run("non-positive limit uses default", func(t *testing.T) {
		t.Parallel()
		body := ReadAllTruncated(strings.NewReader("payload"), -1)
		assert.Equal(t, "payload", string(body))
	})

	t.Run("read error yields partial body", func(t *testing.T) {
		t.Parallel()
		body := ReadAllTruncated(io.MultiReader(strings.NewReader("part"), errReader{}), 100)
		assert.Equal(t, "part", string(body),
			"io.ReadAll returns data read before the error; truncation keeps it for diagnostics")
	})
}
