package era

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewHeldRequestStoreNil(t *testing.T) {
	t.Parallel()
	s := NewHeldRequestStore(nil)
	if _, ok := s.(*memoryHeldStore); !ok {
		t.Fatalf("nil backend should give mem store, got %T", s)
	}
}

func TestNewHeldRequestStoreCache(t *testing.T) {
	t.Parallel()
	s := NewHeldRequestStore(newFakeCache())
	if _, ok := s.(*redisHeldStore); !ok {
		t.Fatalf("cache backend should give redis store, got %T", s)
	}
}

func TestRedisHeldStorePutHappy(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	req := &HeldRequest{UpstreamID: "u1", Method: "sampling/createMessage"}
	if err := s.Put(context.Background(), "id1", req, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.lastSetKey, "mcp:held:") {
		t.Fatalf("key prefix wrong: %q", c.lastSetKey)
	}
	if c.lastSetTTL != time.Minute {
		t.Fatalf("ttl = %v", c.lastSetTTL)
	}
	var got HeldRequest
	_ = json.Unmarshal(c.data[c.lastSetKey], &got)
	if got.UpstreamID != "u1" {
		t.Fatalf("payload round-trip failed: %+v", got)
	}
}

func TestRedisHeldStorePutEmpty(t *testing.T) {
	t.Parallel()
	s := &redisHeldStore{backend: newFakeCache()}
	if err := s.Put(context.Background(), "", nil, time.Minute); err == nil {
		t.Fatal("expected error for empty id/req")
	}
}

func TestRedisHeldStorePutSetError(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	c.setErr = errors.New("set boom")
	s := &redisHeldStore{backend: c}
	err := s.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Minute)
	if err == nil || !contains(err.Error(), "store held request") {
		t.Fatalf("want store held request error, got %v", err)
	}
}

func TestRedisHeldStoreConsumeHappy(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	_ = s.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Minute)
	got, err := s.Consume(context.Background(), "id1")
	if err != nil {
		t.Fatal(err)
	}
	if got.UpstreamID != "u1" {
		t.Fatalf("upstream = %q", got.UpstreamID)
	}
}

func TestRedisHeldStoreConsumeMiss(t *testing.T) {
	t.Parallel()
	s := &redisHeldStore{backend: newFakeCache()}
	if _, err := s.Consume(context.Background(), "missing"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound, got %v", err)
	}
}

func TestRedisHeldStoreConsumeNotConfirmed(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	_ = s.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Minute)
	// Exists returns false → removed==false → ErrHeldConsumed.
	c.existsOverride = boolPtr(false)
	if _, err := s.Consume(context.Background(), "id1"); !errors.Is(err, ErrHeldConsumed) {
		t.Fatalf("want ErrHeldConsumed, got %v", err)
	}
}

func TestRedisHeldStoreConsumeDeleteError(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	_ = s.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Minute)
	c.deleteErr = errors.New("delete boom")
	if _, err := s.Consume(context.Background(), "id1"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound, got %v", err)
	}
}

func TestRedisHeldStoreConsumeBadPayload(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	// Store non-JSON bytes; Delete confirms removed.
	c.data[heldKey("id1")] = []byte("{not json")
	if _, err := s.Consume(context.Background(), "id1"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound for bad payload, got %v", err)
	}
}

func TestDeleteAndConfirmExistsError(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	c.data[heldKey("id1")] = []byte("x")
	c.existsErr = errors.New("exists boom")
	removed, err := deleteAndConfirm(context.Background(), c, heldKey("id1"))
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("exists-error should fall back to existed=true")
	}
}

func TestRedisHeldStoreDelete(t *testing.T) {
	t.Parallel()
	c := newFakeCache()
	s := &redisHeldStore{backend: c}
	if err := s.Delete(context.Background(), "id1"); err != nil {
		t.Fatal(err)
	}
	c.deleteErr = errors.New("delete boom")
	if err := s.Delete(context.Background(), "id1"); err == nil || !contains(err.Error(), "delete held request") {
		t.Fatalf("want delete held request error, got %v", err)
	}
}

func TestMemoryHeldStorePutEmpty(t *testing.T) {
	t.Parallel()
	s := NewMemoryHeldStore()
	if err := s.Put(context.Background(), "", nil, time.Minute); err == nil {
		t.Fatal("expected error for empty id/req")
	}
}

func TestMemoryHeldStoreDelete(t *testing.T) {
	t.Parallel()
	s := NewMemoryHeldStore()
	_ = s.Put(context.Background(), "id1", &HeldRequest{UpstreamID: "u1"}, time.Minute)
	if err := s.Delete(context.Background(), "id1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(context.Background(), "id1"); !errors.Is(err, ErrHeldNotFound) {
		t.Fatalf("want ErrHeldNotFound after Delete, got %v", err)
	}
}
