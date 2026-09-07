package security

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/mcp/envelope"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// ---------------------------------------------------------------------------
// Vault fakes for shared-key tests.
// ---------------------------------------------------------------------------

// fakeVaultClient implements vault.Client for shared-key tests.
type fakeVaultClient struct {
	enabled bool
	kv      vault.KVClient
	transit vault.TransitClient
}

func (f *fakeVaultClient) IsEnabled() bool                      { return f.enabled }
func (f *fakeVaultClient) Authenticate(_ context.Context) error { return nil }
func (f *fakeVaultClient) RenewToken(_ context.Context) error   { return nil }
func (f *fakeVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) {
	return nil, nil
}
func (f *fakeVaultClient) PKI() vault.PKIClient         { return nil }
func (f *fakeVaultClient) KV() vault.KVClient           { return f.kv }
func (f *fakeVaultClient) Transit() vault.TransitClient { return f.transit }
func (f *fakeVaultClient) Close() error                 { return nil }

// fakeKV implements vault.KVClient.
type fakeKV struct {
	data map[string]interface{}
	err  error
}

func (f *fakeKV) Read(_ context.Context, _, _ string) (map[string]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}
func (f *fakeKV) Write(_ context.Context, _, _ string, _ map[string]interface{}) error { return nil }
func (f *fakeKV) Delete(_ context.Context, _, _ string) error                          { return nil }
func (f *fakeKV) List(_ context.Context, _, _ string) ([]string, error)                { return nil, nil }

// fakeTransit implements vault.TransitClient.
type fakeTransit struct {
	sig []byte
	err error
}

func (f *fakeTransit) Encrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, nil
}
func (f *fakeTransit) Decrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, nil
}
func (f *fakeTransit) Sign(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sig, nil
}
func (f *fakeTransit) Verify(_ context.Context, _, _ string, _, _ []byte) (bool, error) {
	return true, nil
}

func fullKey() []byte {
	key := make([]byte, envelope.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// ---------------------------------------------------------------------------
// sharedkey.go
// ---------------------------------------------------------------------------

func TestLoadSharedKeyUnknownSource(t *testing.T) {
	t.Parallel()
	cfg := &config.MCPSharedKey{Source: "bogus"}
	_, err := LoadSharedKey(context.Background(), cfg, nil)
	if err == nil || !contains(err.Error(), "unknown shared key source") {
		t.Fatalf("want unknown shared key source error, got %v", err)
	}
}

func TestLoadSharedKeyEmptySource(t *testing.T) {
	t.Parallel()
	cfg := &config.MCPSharedKey{Source: ""}
	_, err := LoadSharedKey(context.Background(), cfg, nil)
	if !errors.Is(err, ErrNoSharedKey) {
		t.Fatalf("want ErrNoSharedKey, got %v", err)
	}
}

func TestLoadKVKey(t *testing.T) {
	t.Parallel()
	key := fullKey()
	enc := base64.StdEncoding.EncodeToString(key)

	tests := []struct {
		name    string
		cfg     *config.MCPSharedKey
		vc      vault.Client
		wantErr string
	}{
		{
			name: "happy default field",
			cfg:  &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:   &fakeVaultClient{enabled: true, kv: &fakeKV{data: map[string]interface{}{"key": enc}}},
		},
		{
			name: "custom field",
			cfg:  &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p", VaultField: "mykey"},
			vc:   &fakeVaultClient{enabled: true, kv: &fakeKV{data: map[string]interface{}{"mykey": enc}}},
		},
		{
			name:    "vault disabled",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:      &fakeVaultClient{enabled: false},
			wantErr: "vault client unavailable",
		},
		{
			name:    "nil vc",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:      nil,
			wantErr: "vault client unavailable",
		},
		{
			name:    "missing mount",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "", VaultPath: "p"},
			vc:      &fakeVaultClient{enabled: true, kv: &fakeKV{}},
			wantErr: "requires vaultMount and vaultPath",
		},
		{
			name:    "field not found",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:      &fakeVaultClient{enabled: true, kv: &fakeKV{data: map[string]interface{}{"other": enc}}},
			wantErr: "not found",
		},
		{
			name:    "field not a string",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:      &fakeVaultClient{enabled: true, kv: &fakeKV{data: map[string]interface{}{"key": 123}}},
			wantErr: "is not a string",
		},
		{
			name:    "read error",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultKV, VaultMount: "secret", VaultPath: "p"},
			vc:      &fakeVaultClient{enabled: true, kv: &fakeKV{err: errors.New("boom")}},
			wantErr: "read shared key from vault",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := LoadSharedKey(context.Background(), tt.cfg, tt.vc)
			if tt.wantErr != "" {
				if err == nil || !contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != envelope.KeySize {
				t.Fatalf("key size %d", len(got))
			}
		})
	}
}

func TestDeriveTransitKey(t *testing.T) {
	t.Parallel()
	sig := []byte("deterministic-signature-bytes")

	tests := []struct {
		name    string
		cfg     *config.MCPSharedKey
		vc      vault.Client
		wantErr string
	}{
		{
			name: "happy",
			cfg:  &config.MCPSharedKey{Source: config.MCPKeySourceVaultTransit, VaultMount: "transit", VaultPath: "k"},
			vc:   &fakeVaultClient{enabled: true, transit: &fakeTransit{sig: sig}},
		},
		{
			name:    "disabled",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultTransit, VaultMount: "transit", VaultPath: "k"},
			vc:      &fakeVaultClient{enabled: false},
			wantErr: "vault client unavailable",
		},
		{
			name:    "nil vc",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultTransit, VaultMount: "transit", VaultPath: "k"},
			vc:      nil,
			wantErr: "vault client unavailable",
		},
		{
			name:    "missing mount",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultTransit, VaultMount: "", VaultPath: "k"},
			vc:      &fakeVaultClient{enabled: true, transit: &fakeTransit{sig: sig}},
			wantErr: "requires vaultMount and vaultPath",
		},
		{
			name:    "sign error",
			cfg:     &config.MCPSharedKey{Source: config.MCPKeySourceVaultTransit, VaultMount: "transit", VaultPath: "k"},
			vc:      &fakeVaultClient{enabled: true, transit: &fakeTransit{err: errors.New("boom")}},
			wantErr: "derive shared key via transit",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := LoadSharedKey(context.Background(), tt.cfg, tt.vc)
			if tt.wantErr != "" {
				if err == nil || !contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != envelope.KeySize {
				t.Fatalf("key size %d", len(got))
			}
			// Deterministic given fixed sig.
			got2, _ := LoadSharedKey(context.Background(), tt.cfg, tt.vc)
			if string(got) != string(got2) {
				t.Fatal("transit key not deterministic")
			}
		})
	}
}

func TestDecodeInlineKeyRawURLFallback(t *testing.T) {
	t.Parallel()
	key := fullKey()
	// Raw-url encoding (no padding) so StdEncoding fails first.
	enc := base64.RawURLEncoding.EncodeToString(key)
	cfg := &config.MCPSharedKey{Source: config.MCPKeySourceInline, Value: enc}
	got, err := LoadSharedKey(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != envelope.KeySize {
		t.Fatalf("key size %d", len(got))
	}
}

func TestDecodeInlineKeyEmpty(t *testing.T) {
	t.Parallel()
	cfg := &config.MCPSharedKey{Source: config.MCPKeySourceInline, Value: ""}
	_, err := LoadSharedKey(context.Background(), cfg, nil)
	if err == nil || !contains(err.Error(), "inline shared key is empty") {
		t.Fatalf("want empty error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// icon.go
// ---------------------------------------------------------------------------

func TestSanitizeIconsEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		input       json.RawMessage
		wantDropped int
		wantSame    bool
	}{
		{name: "nil", input: nil, wantDropped: 0, wantSame: true},
		{name: "empty", input: json.RawMessage(""), wantDropped: 0, wantSame: true},
		{name: "non-object array", input: json.RawMessage("[1,2]"), wantDropped: 0, wantSame: true},
		{name: "invalid json", input: json.RawMessage("{bad"), wantDropped: 0, wantSame: true},
		{name: "no icons key", input: json.RawMessage(`{"x":1}`), wantDropped: 0, wantSame: true},
		{name: "all kept n==0", input: json.RawMessage(`{"icons":[{"src":"https://ok/i.png"}]}`), wantDropped: 0, wantSame: true},
		{name: "non-array icons", input: json.RawMessage(`{"icons":{"a":1}}`), wantDropped: 0, wantSame: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, dropped := SanitizeIcons(tt.input)
			if dropped != tt.wantDropped {
				t.Fatalf("dropped=%d want %d", dropped, tt.wantDropped)
			}
			if tt.wantSame && string(out) != string(tt.input) {
				t.Fatalf("expected unchanged output, got %q", string(out))
			}
		})
	}
}

func TestIconAllowedCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		icon json.RawMessage
		want bool
	}{
		{name: "malformed object", icon: json.RawMessage(`"not-an-object"`), want: false},
		{name: "no src or uri", icon: json.RawMessage(`{"name":"x"}`), want: true},
		{name: "uri fallback allowed", icon: json.RawMessage(`{"uri":"https://ok/i.png"}`), want: true},
		{name: "uri fallback disallowed", icon: json.RawMessage(`{"uri":"http://bad/i.png"}`), want: false},
		{name: "src allowed", icon: json.RawMessage(`{"src":"https://ok/i.png"}`), want: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := iconAllowed(tt.icon); got != tt.want {
				t.Fatalf("iconAllowed=%v want %v", got, tt.want)
			}
		})
	}
}

func TestIsAllowedIconURIUnparseable(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"ht tp://%zz": false,
		"://":         false,
		"https://ok":  true,
	}
	for uri, want := range cases {
		if got := IsAllowedIconURI(uri); got != want {
			t.Errorf("IsAllowedIconURI(%q)=%v want %v", uri, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// schema.go
// ---------------------------------------------------------------------------

func TestValidateSchemaWalkArray(t *testing.T) {
	t.Parallel()
	schema := json.RawMessage(`{"anyOf":[{"type":"string"},{"$ref":"https://evil"}]}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 10, MaxNodes: 100}); !errors.Is(err, ErrSchemaNetworkRef) {
		t.Fatalf("want ErrSchemaNetworkRef, got %v", err)
	}
}

func TestValidateSchemaInvalidJSON(t *testing.T) {
	t.Parallel()
	if err := ValidateSchema(json.RawMessage("{not json"), SchemaLimits{}); !errors.Is(err, ErrSchemaNetworkRef) {
		t.Fatalf("want ErrSchemaNetworkRef, got %v", err)
	}
}

func TestValidateSchemaWithBudgetDeadlineSet(t *testing.T) {
	t.Parallel()
	// A generous budget on a non-empty schema exercises the deadline-set arm of
	// ValidateSchema (line 60) without tripping the budget.
	schema := json.RawMessage(`{"type":"object","properties":{"a":{"type":"string"}}}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 10, MaxNodes: 100, Budget: time.Hour}); err != nil {
		t.Fatalf("schema with generous budget rejected: %v", err)
	}
}

func TestValidateSchemaValidArray(t *testing.T) {
	t.Parallel()
	// anyOf with only benign subschemas: walkArray recurses and completes nil.
	schema := json.RawMessage(`{"anyOf":[{"type":"string"},{"type":"number"}]}`)
	if err := ValidateSchema(schema, SchemaLimits{MaxDepth: 10, MaxNodes: 100}); err != nil {
		t.Fatalf("valid array schema rejected: %v", err)
	}
}

func TestValidateSchemaTopLevelScalar(t *testing.T) {
	t.Parallel()
	if err := ValidateSchema(json.RawMessage("42"), SchemaLimits{MaxDepth: 10, MaxNodes: 10}); err != nil {
		t.Fatalf("scalar schema should be valid: %v", err)
	}
}

// TestValidateSchemaBudgetExceeded exercises the checkBounds budget arm using an
// in-package white-box schemaWalker whose clock is monotonically advanced past
// the deadline. ValidateSchema itself hardcodes time.Now (no clock seam), so we
// drive the walker directly to keep the test deterministic (§3C / §5.3).
func TestValidateSchemaBudgetExceeded(t *testing.T) {
	t.Parallel()
	base := time.Unix(0, 0)
	calls := 0
	w := &schemaWalker{
		limits: SchemaLimits{Budget: 1},
		now: func() time.Time {
			calls++
			// First call sets the deadline; later calls are past it.
			if calls == 1 {
				return base
			}
			return base.Add(time.Hour)
		},
	}
	w.deadline = w.now().Add(w.limits.Budget)
	node := map[string]any{"a": map[string]any{"b": 1}}
	if err := w.walk(node, 0); !errors.Is(err, ErrSchemaBudgetExceeded) {
		t.Fatalf("want ErrSchemaBudgetExceeded, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// redact.go
// ---------------------------------------------------------------------------

func TestRedactArgsNil(t *testing.T) {
	t.Parallel()
	if RedactArgs(nil) != nil {
		t.Fatal("RedactArgs(nil) should be nil")
	}
}

func TestArgumentDigestNil(t *testing.T) {
	t.Parallel()
	d1 := ArgumentDigest(nil)
	d2 := ArgumentDigest(nil)
	if d1 == "" {
		t.Fatal("digest of nil should be non-empty (marshals to null)")
	}
	if d1 != d2 {
		t.Fatal("digest of nil should be stable")
	}
}

// ---------------------------------------------------------------------------
// drift.go
// ---------------------------------------------------------------------------

func TestCanonicalHashArrayAndScalars(t *testing.T) {
	t.Parallel()
	s := NewDriftStore(false)
	def1 := json.RawMessage(`{"arr":[1,true,null,"s"],"n":1.5}`)
	def2 := json.RawMessage(`{"n":1.5,"arr":[1,true,null,"s"]}`) // reordered keys
	r1 := s.Observe("up", "t", def1)
	r2 := s.Observe("up", "t", def2)
	if r1.Hash != r2.Hash {
		t.Fatalf("reordered keys should hash identically: %s vs %s", r1.Hash, r2.Hash)
	}
	if r2.Changed {
		t.Fatal("reordered-key def should not be a change")
	}
}

func TestCanonicalHashInvalidJSONFallback(t *testing.T) {
	t.Parallel()
	h1 := CanonicalHash(json.RawMessage("{bad"))
	h2 := CanonicalHash(json.RawMessage("{bad"))
	if h1 == "" || h1 != h2 {
		t.Fatalf("invalid-JSON fallback hash should be stable and non-empty: %s vs %s", h1, h2)
	}
}

// ---------------------------------------------------------------------------
// trust.go
// ---------------------------------------------------------------------------

func TestApplyTrustPolicyInvalidJSONItem(t *testing.T) {
	t.Parallel()
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustUntrusted}
	item := json.RawMessage("{bad")
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyStrip, item)
	if string(out) != string(item) {
		t.Fatalf("invalid JSON item should be returned unchanged, got %q", string(out))
	}
}

func TestApplyTrustPolicyNoUntrustedFields(t *testing.T) {
	t.Parallel()
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustUntrusted}
	item := json.RawMessage(`{"name":"t"}`)
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyStrip, item)
	if string(out) != string(item) {
		t.Fatalf("item with no untrusted fields should be unchanged, got %q", string(out))
	}
}

func TestFlagFieldNonString(t *testing.T) {
	t.Parallel()
	cfg := config.MCPBackend{TrustLevel: config.MCPTrustUntrusted}
	item := json.RawMessage(`{"name":"t","annotations":{"a":1}}`)
	out := ApplyTrustPolicy(cfg, config.MCPTrustPolicyFlag, item)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["annotations"]; ok {
		t.Fatal("non-string annotations should be deleted")
	}
	if _, ok := obj["name"]; !ok {
		t.Fatal("name should be preserved")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
