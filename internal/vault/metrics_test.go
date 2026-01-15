package vault

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRecordRequest(t *testing.T) {
	// Test that recording doesn't panic
	assert.NotPanics(t, func() {
		RecordRequest("read", 100*time.Millisecond, true)
		RecordRequest("read", 100*time.Millisecond, false)
		RecordRequest("write", 200*time.Millisecond, true)
		RecordRequest("delete", 50*time.Millisecond, true)
		RecordRequest("list", 150*time.Millisecond, false)
	})
}

func TestRecordAuthentication(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordAuthentication("kubernetes", true)
		RecordAuthentication("kubernetes", false)
		RecordAuthentication("token", true)
		RecordAuthentication("approle", true)
	})
}

func TestUpdateSecretsWatched(t *testing.T) {
	assert.NotPanics(t, func() {
		UpdateSecretsWatched(0)
		UpdateSecretsWatched(5)
		UpdateSecretsWatched(10)
	})
}

func TestRecordSecretRefresh(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordSecretRefresh("secret/path1", true)
		RecordSecretRefresh("secret/path1", false)
		RecordSecretRefresh("secret/path2", true)
	})
}

func TestRecordCacheHit(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordCacheHit()
		RecordCacheHit()
		RecordCacheHit()
	})
}

func TestRecordCacheMiss(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordCacheMiss()
		RecordCacheMiss()
		RecordCacheMiss()
	})
}

func TestUpdateTokenExpiry(t *testing.T) {
	assert.NotPanics(t, func() {
		UpdateTokenExpiry(time.Now().Add(1 * time.Hour))
		UpdateTokenExpiry(time.Time{}) // Zero time
	})
}

func TestRecordRetry(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordRetry("read", 1)
		RecordRetry("read", 2)
		RecordRetry("write", 1)
	})
}

func TestRecordConnectionError(t *testing.T) {
	assert.NotPanics(t, func() {
		RecordConnectionError()
		RecordConnectionError()
	})
}
