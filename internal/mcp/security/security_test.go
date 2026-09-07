package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
)

func TestIsSensitiveKey(t *testing.T) {
	cases := map[string]bool{
		"token":        true,
		"apiKey":       true,
		"password":     true,
		"requestState": true,
		"name":         false,
		"query":        false,
	}
	for k, want := range cases {
		if got := IsSensitiveKey(k); got != want {
			t.Errorf("IsSensitiveKey(%q)=%v want %v", k, got, want)
		}
	}
}

func TestRedactArgs(t *testing.T) {
	args := map[string]any{
		"token": "abc",
		"query": "hello",
		"nested": map[string]any{
			"password": "p",
			"keep":     "ok",
		},
	}
	out := RedactArgs(args)
	if out["token"] != RedactedValue {
		t.Errorf("token not redacted: %v", out["token"])
	}
	if out["query"] != "hello" {
		t.Errorf("query changed: %v", out["query"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["password"] != RedactedValue || nested["keep"] != "ok" {
		t.Errorf("nested redaction failed: %v", out["nested"])
	}
	// Original not mutated.
	if args["token"] != "abc" {
		t.Errorf("original mutated: %v", args["token"])
	}
}

func TestArgumentDigestStableAndRedacted(t *testing.T) {
	a := map[string]any{"token": "secret1", "q": "x"}
	b := map[string]any{"token": "secret2", "q": "x"}
	// Digests must match because the token is redacted before hashing.
	if ArgumentDigest(a) != ArgumentDigest(b) {
		t.Error("digest depends on redacted secret material")
	}
	if ArgumentDigest(a) == "" {
		t.Error("empty digest")
	}
}

func TestRedactToken(t *testing.T) {
	if RedactToken("") != "" {
		t.Error("empty token should yield empty")
	}
	if RedactToken("abc") == "abc" {
		t.Error("token leaked")
	}
}

func TestIsAllowedIconURI(t *testing.T) {
	cases := map[string]bool{
		"https://example.com/i.png":  true,
		"data:image/png;base64,AAAA": true,
		"http://example.com/i.png":   false,
		"file:///etc/passwd":         false,
		"ftp://x/y":                  false,
		"":                           false,
	}
	for uri, want := range cases {
		if got := IsAllowedIconURI(uri); got != want {
			t.Errorf("IsAllowedIconURI(%q)=%v want %v", uri, got, want)
		}
	}
}

func TestSanitizeIcons(t *testing.T) {
	result := json.RawMessage(`{"icons":[{"src":"https://ok/i.png"},{"src":"http://bad/i.png"}],"x":1}`)
	out, dropped := SanitizeIcons(result)
	if dropped != 1 {
		t.Fatalf("dropped=%d want 1", dropped)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	var icons []json.RawMessage
	_ = json.Unmarshal(obj["icons"], &icons)
	if len(icons) != 1 {
		t.Errorf("expected 1 icon kept, got %d", len(icons))
	}
}

func TestValidateSchemaNetworkRef(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"a":{"$ref":"https://evil/x"}}}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 10, MaxNodes: 100}); err != ErrSchemaNetworkRef {
		t.Errorf("want ErrSchemaNetworkRef, got %v", err)
	}
}

func TestValidateSchemaLocalRefOK(t *testing.T) {
	schema := json.RawMessage(`{"$ref":"#/definitions/x","definitions":{"x":{"type":"string"}}}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 10, MaxNodes: 100}); err != nil {
		t.Errorf("local ref rejected: %v", err)
	}
}

func TestValidateSchemaDepth(t *testing.T) {
	schema := json.RawMessage(`{"a":{"b":{"c":{"d":1}}}}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 2}); err != ErrSchemaTooDeep {
		t.Errorf("want ErrSchemaTooDeep, got %v", err)
	}
}

func TestValidateSchemaNodes(t *testing.T) {
	schema := json.RawMessage(`{"a":1,"b":2,"c":3,"d":4}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxNodes: 2}); err != ErrSchemaTooManyNodes {
		t.Errorf("want ErrSchemaTooManyNodes, got %v", err)
	}
}

func TestDriftStore(t *testing.T) {
	s := NewDriftStore(false)
	def1 := json.RawMessage(`{"name":"t","desc":"a"}`)
	def2 := json.RawMessage(`{"desc":"a","name":"t"}`) // reordered keys, same logical def
	def3 := json.RawMessage(`{"name":"t","desc":"b"}`)

	r1 := s.Observe("up", "t", def1)
	if r1.Changed {
		t.Error("first observation should not be a change")
	}
	r2 := s.Observe("up", "t", def2)
	if r2.Changed {
		t.Error("reordered keys should hash the same")
	}
	r3 := s.Observe("up", "t", def3)
	if !r3.Changed {
		t.Error("changed def should be detected")
	}
	if r3.Exclude {
		t.Error("non-reapproval mode should not exclude")
	}
}

func TestDriftStoreReapproval(t *testing.T) {
	s := NewDriftStore(true)
	s.Observe("up", "t", json.RawMessage(`{"v":1}`))
	r := s.Observe("up", "t", json.RawMessage(`{"v":2}`))
	if !r.Changed || !r.Exclude {
		t.Fatalf("expected changed+excluded, got %+v", r)
	}
	s.Approve("up", "t", r.Hash)
	r2 := s.Observe("up", "t", json.RawMessage(`{"v":2}`))
	if r2.Changed {
		t.Error("approved hash re-observed should not be a change")
	}
}

func TestApplyTrustPolicyStrip(t *testing.T) {
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustUntrusted}
	item := json.RawMessage(`{"name":"t","description":"do X","title":"T"}`)
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyStrip, item)
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out, &obj)
	if _, ok := obj["description"]; ok {
		t.Error("description should be stripped")
	}
	if _, ok := obj["name"]; !ok {
		t.Error("name should be preserved")
	}
}

func TestApplyTrustPolicyFlag(t *testing.T) {
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustUntrusted}
	item := json.RawMessage(`{"name":"t","description":"do X"}`)
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyFlag, item)
	var obj map[string]string
	_ = json.Unmarshal(out, &obj)
	if obj["description"] != untrustedFlagPrefix+"do X" {
		t.Errorf("description not flagged: %q", obj["description"])
	}
}

func TestApplyTrustPolicyTrustedUnchanged(t *testing.T) {
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustTrusted}
	item := json.RawMessage(`{"name":"t","description":"do X"}`)
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyStrip, item)
	if string(out) != string(item) {
		t.Error("trusted upstream should be unchanged")
	}
}

func TestLoadSharedKeyInline(t *testing.T) {
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	cfg := &config.MCPSharedKey{
		Source: config.MCPKeySourceInline,
		Value:  base64.StdEncoding.EncodeToString(key),
	}
	got, err := LoadSharedKey(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != envelope.KeySize {
		t.Errorf("key size %d", len(got))
	}
}

func TestLoadSharedKeyNoConfig(t *testing.T) {
	if _, err := LoadSharedKey(context.Background(), nil, nil); err != ErrNoSharedKey {
		t.Errorf("want ErrNoSharedKey, got %v", err)
	}
}

func TestLoadSharedKeyInlineBadLength(t *testing.T) {
	cfg := &config.MCPSharedKey{
		Source: config.MCPKeySourceInline,
		Value:  base64.StdEncoding.EncodeToString([]byte("short")),
	}
	if _, err := LoadSharedKey(context.Background(), cfg, nil); err == nil {
		t.Error("expected error for short key")
	}
}

func TestGenerateKey(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != envelope.KeySize {
		t.Errorf("key size %d", len(k))
	}
}

func TestSchemaBudget(t *testing.T) {
	// A zero-length schema is trivially valid.
	if err := ValidateSchema(nil, SchemaLimits{Budget: time.Nanosecond}); err != nil {
		t.Errorf("empty schema should be valid: %v", err)
	}
}
