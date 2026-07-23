package redisclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// mockKVClient implements vault.KVClient for testing.
type mockKVClient struct {
	data map[string]map[string]interface{}
	err  error
}

func (m *mockKVClient) Read(_ context.Context, mount, path string) (map[string]interface{}, error) {
	if m.err != nil {
		return nil, m.err
	}
	if secret, ok := m.data[mount+"/"+path]; ok {
		return secret, nil
	}
	return nil, errors.New("secret not found")
}

func (m *mockKVClient) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return nil
}

func (m *mockKVClient) Delete(_ context.Context, _, _ string) error { return nil }

func (m *mockKVClient) List(_ context.Context, _, _ string) ([]string, error) { return nil, nil }

// mockVaultClient implements vault.Client for testing.
type mockVaultClient struct {
	enabled bool
	kv      *mockKVClient
}

func (m *mockVaultClient) IsEnabled() bool                                       { return m.enabled }
func (m *mockVaultClient) Authenticate(_ context.Context) error                  { return nil }
func (m *mockVaultClient) RenewToken(_ context.Context) error                    { return nil }
func (m *mockVaultClient) Health(_ context.Context) (*vault.HealthStatus, error) { return nil, nil }
func (m *mockVaultClient) PKI() vault.PKIClient                                  { return nil }
func (m *mockVaultClient) KV() vault.KVClient                                    { return m.kv }
func (m *mockVaultClient) Transit() vault.TransitClient                          { return nil }
func (m *mockVaultClient) Close() error                                          { return nil }

func testLogger() observability.Logger { return observability.NopLogger() }

// --- FromRateLimitRedisConfig / FromRedisCacheConfig mapping ---

func TestFromRateLimitRedisConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if FromRateLimitRedisConfig(nil) != nil {
			t.Fatal("expected nil config")
		}
	})

	t.Run("full mapping", func(t *testing.T) {
		retryCfg := &config.RedisRetryConfig{MaxRetries: 5}
		sentinel := &config.RedisSentinelConfig{MasterName: "mymaster"}
		tlsCfg := &config.TLSConfig{Enabled: true}
		src := &config.RateLimitRedisConfig{
			URL:               "redis://localhost:6379",
			Sentinel:          sentinel,
			PoolSize:          7,
			ConnectTimeout:    config.Duration(time.Second),
			ReadTimeout:       config.Duration(2 * time.Second),
			WriteTimeout:      config.Duration(3 * time.Second),
			TLS:               tlsCfg,
			PasswordVaultPath: "secret/redis",
			Retry:             retryCfg,
		}

		got := FromRateLimitRedisConfig(src)

		if got.URL != src.URL || got.Sentinel != sentinel || got.PoolSize != 7 {
			t.Errorf("basic fields not mapped: %+v", got)
		}
		if got.ConnectTimeout != time.Second || got.ReadTimeout != 2*time.Second ||
			got.WriteTimeout != 3*time.Second {
			t.Errorf("timeouts not mapped: %+v", got)
		}
		if got.TLS != tlsCfg || got.PasswordVaultPath != "secret/redis" || got.Retry != retryCfg {
			t.Errorf("tls/vault/retry not mapped: %+v", got)
		}
	})
}

func TestFromRedisCacheConfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if FromRedisCacheConfig(nil) != nil {
			t.Fatal("expected nil config")
		}
	})

	t.Run("full mapping", func(t *testing.T) {
		sentinel := &config.RedisSentinelConfig{MasterName: "mymaster"}
		src := &config.RedisCacheConfig{
			URL:               "redis://localhost:6379",
			Sentinel:          sentinel,
			PoolSize:          9,
			ConnectTimeout:    config.Duration(time.Second),
			ReadTimeout:       config.Duration(2 * time.Second),
			WriteTimeout:      config.Duration(3 * time.Second),
			PasswordVaultPath: "secret/cache",
			Retry:             &config.RedisRetryConfig{MaxRetries: 2},
		}

		got := FromRedisCacheConfig(src)

		if got.URL != src.URL || got.Sentinel != sentinel || got.PoolSize != 9 {
			t.Errorf("basic fields not mapped: %+v", got)
		}
		if got.PasswordVaultPath != "secret/cache" || got.Retry != src.Retry {
			t.Errorf("vault/retry not mapped: %+v", got)
		}
	})
}

// --- Options mapping (standalone + sentinel construction paths) ---

func TestBuildStandaloneOptions(t *testing.T) {
	cfg := &Config{
		URL:            "redis://user:pass@localhost:6379/2",
		PoolSize:       11,
		ConnectTimeout: time.Second,
		ReadTimeout:    50 * time.Millisecond,
		WriteTimeout:   60 * time.Millisecond,
	}

	opts, err := BuildStandaloneOptions(cfg)
	if err != nil {
		t.Fatalf("BuildStandaloneOptions: %v", err)
	}

	if opts.Addr != "localhost:6379" || opts.DB != 2 {
		t.Errorf("URL not parsed: addr=%s db=%d", opts.Addr, opts.DB)
	}
	if opts.Username != "user" || opts.Password != "pass" {
		t.Errorf("credentials not parsed: %s/%s", opts.Username, opts.Password)
	}
	if opts.PoolSize != 11 || opts.DialTimeout != time.Second {
		t.Errorf("pool options not applied: pool=%d dial=%v", opts.PoolSize, opts.DialTimeout)
	}
	if opts.ReadTimeout != 50*time.Millisecond || opts.WriteTimeout != 60*time.Millisecond {
		t.Errorf("timeouts not applied: read=%v write=%v", opts.ReadTimeout, opts.WriteTimeout)
	}
	if opts.TLSConfig != nil {
		t.Error("TLS should not be configured")
	}
}

func TestBuildStandaloneOptions_InvalidURL(t *testing.T) {
	_, err := BuildStandaloneOptions(&Config{URL: "://bad"})
	if err == nil || !strings.Contains(err.Error(), "invalid redis URL") {
		t.Fatalf("expected invalid URL error, got %v", err)
	}
}

func TestBuildStandaloneOptions_TLS(t *testing.T) {
	cfg := &Config{
		URL: "redis://localhost:6379",
		TLS: &config.TLSConfig{Enabled: true, InsecureSkipVerify: true},
	}

	opts, err := BuildStandaloneOptions(cfg)
	if err != nil {
		t.Fatalf("BuildStandaloneOptions: %v", err)
	}
	if opts.TLSConfig == nil || !opts.TLSConfig.InsecureSkipVerify {
		t.Error("TLS config not applied")
	}
}

func TestBuildFailoverOptions(t *testing.T) {
	cfg := &Config{
		Sentinel: &config.RedisSentinelConfig{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"s1:26379", "s2:26379"},
			SentinelPassword: "sentinel-pw",
			Password:         "master-pw",
			DB:               3,
		},
		PoolSize:       13,
		ConnectTimeout: 2 * time.Second,
		ReadTimeout:    70 * time.Millisecond,
		WriteTimeout:   80 * time.Millisecond,
		TLS:            &config.TLSConfig{Enabled: true},
	}

	opts, err := BuildFailoverOptions(cfg, nil)
	if err != nil {
		t.Fatalf("BuildFailoverOptions: %v", err)
	}

	if opts.MasterName != "mymaster" || len(opts.SentinelAddrs) != 2 {
		t.Errorf("sentinel identity not mapped: %+v", opts)
	}
	if opts.SentinelPassword != "sentinel-pw" || opts.Password != "master-pw" || opts.DB != 3 {
		t.Errorf("credentials not mapped: %+v", opts)
	}
	if opts.PoolSize != 13 || opts.DialTimeout != 2*time.Second {
		t.Errorf("pool options not mapped: %+v", opts)
	}
	if opts.ReadTimeout != 70*time.Millisecond || opts.WriteTimeout != 80*time.Millisecond {
		t.Errorf("timeouts not mapped: %+v", opts)
	}
	if opts.TLSConfig == nil {
		t.Error("TLS config not applied")
	}
	if opts.Dialer != nil {
		t.Error("dialer should be nil when not provided")
	}
}

func TestBuildFailoverOptions_Dialer(t *testing.T) {
	cfg := &Config{Sentinel: &config.RedisSentinelConfig{MasterName: "m"}}
	dialCalled := false
	opts, err := BuildFailoverOptions(cfg, func(_ context.Context, _, _ string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("test dialer")
	})
	if err != nil {
		t.Fatalf("BuildFailoverOptions: %v", err)
	}
	if opts.Dialer == nil {
		t.Fatal("dialer not applied")
	}
	_, _ = opts.Dialer(context.Background(), "tcp", "x")
	if !dialCalled {
		t.Error("dialer not invoked")
	}
}

// --- New (construction + ping) ---

func TestNew_NilConfig(t *testing.T) {
	_, err := New(context.Background(), nil, testLogger())
	if err == nil || !strings.Contains(err.Error(), "redis configuration is required") {
		t.Fatalf("expected config-required error, got %v", err)
	}
}

func TestNew_MissingURL(t *testing.T) {
	_, err := New(context.Background(), &Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "redis URL is required") {
		t.Fatalf("expected URL-required error, got %v", err)
	}
}

func TestNew_Standalone(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := New(context.Background(), &Config{URL: "redis://" + mr.Addr()}, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestNew_PingRequired_Unreachable(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	cfg := &Config{
		URL: "redis://" + addr,
		Retry: &config.RedisRetryConfig{
			MaxRetries:     1,
			InitialBackoff: config.Duration(time.Millisecond),
			MaxBackoff:     config.Duration(2 * time.Millisecond),
		},
	}

	_, err := New(context.Background(), cfg, testLogger(), WithPingMode(PingRequired))
	if err == nil || !strings.Contains(err.Error(), "redis connection failed") {
		t.Fatalf("expected connection failure, got %v", err)
	}
}

func TestNew_PingBestEffort_Unreachable(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	cfg := &Config{
		URL: "redis://" + addr,
		Retry: &config.RedisRetryConfig{
			MaxRetries:     1,
			InitialBackoff: config.Duration(time.Millisecond),
			MaxBackoff:     config.Duration(2 * time.Millisecond),
		},
	}

	client, err := New(context.Background(), cfg, testLogger(), WithPingMode(PingBestEffort))
	if err != nil {
		t.Fatalf("best-effort mode must not fail on connectivity: %v", err)
	}
	defer func() { _ = client.Close() }()
}

func TestNew_Standalone_WithDialer(t *testing.T) {
	mr := miniredis.RunT(t)

	var dialCount atomic.Int32
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialCount.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}

	client, err := New(context.Background(),
		&Config{URL: "redis://" + mr.Addr()},
		testLogger(), WithDialer(dialer))
	if err != nil {
		t.Fatalf("New with custom dialer: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping through custom dialer: %v", err)
	}
	if dialCount.Load() == 0 {
		t.Error("custom dialer must be invoked for standalone connections")
	}
}

func TestNew_ContextCanceled(t *testing.T) {
	mr := miniredis.RunT(t)
	addr := mr.Addr()
	mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &Config{
		URL: "redis://" + addr,
		Retry: &config.RedisRetryConfig{
			MaxRetries:     3,
			InitialBackoff: config.Duration(time.Second),
		},
	}

	_, err := New(ctx, cfg, testLogger(), WithPingMode(PingRequired))
	if err == nil {
		t.Fatal("expected error with canceled context")
	}
}

// --- Vault password resolution ---

func TestNew_VaultPassword_Standalone(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cret")

	vc := &mockVaultClient{
		enabled: true,
		kv: &mockKVClient{data: map[string]map[string]interface{}{
			"secret/redis": {"password": "s3cret"},
		}},
	}

	client, err := New(context.Background(),
		&Config{URL: "redis://" + mr.Addr(), PasswordVaultPath: "secret/redis"},
		testLogger(), WithVaultClient(vc))
	if err != nil {
		t.Fatalf("New with vault password: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("authenticated ping: %v", err)
	}
}

func TestNew_VaultPassword_DoesNotMutateCaller(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("s3cret")

	vc := &mockVaultClient{
		enabled: true,
		kv: &mockKVClient{data: map[string]map[string]interface{}{
			"secret/redis": {"password": "s3cret"},
		}},
	}

	cfg := &Config{
		URL:               "redis://" + mr.Addr(),
		PasswordVaultPath: "secret/redis",
		Sentinel:          nil,
	}
	client, err := New(context.Background(), cfg, testLogger(), WithVaultClient(vc))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if strings.Contains(cfg.URL, "s3cret") {
		t.Error("caller config was mutated with the resolved secret")
	}
}

func TestNew_VaultPassword_SentinelCopyNotMutated(t *testing.T) {
	sentinel := &config.RedisSentinelConfig{
		MasterName:        "mymaster",
		SentinelAddrs:     []string{"127.0.0.1:1"},
		PasswordVaultPath: "secret/master",
	}
	vc := &mockVaultClient{
		enabled: true,
		kv: &mockKVClient{data: map[string]map[string]interface{}{
			"secret/master": {"password": "master-pw"},
		}},
	}

	cfg := &Config{
		Sentinel:       sentinel,
		ConnectTimeout: 20 * time.Millisecond,
		ReadTimeout:    20 * time.Millisecond,
		Retry: &config.RedisRetryConfig{
			MaxRetries:     1,
			InitialBackoff: config.Duration(time.Millisecond),
		},
	}
	client, err := New(context.Background(), cfg, testLogger(),
		WithVaultClient(vc), WithPingMode(PingBestEffort))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	if sentinel.Password != "" {
		t.Error("caller sentinel config was mutated with the resolved secret")
	}
}

func TestNew_VaultError_Fatal(t *testing.T) {
	vc := &mockVaultClient{
		enabled: true,
		kv:      &mockKVClient{err: errors.New("vault sealed")},
	}

	_, err := New(context.Background(),
		&Config{URL: "redis://localhost:6379", PasswordVaultPath: "secret/redis"},
		testLogger(), WithVaultClient(vc), WithPingMode(PingBestEffort))
	if err == nil || !strings.Contains(err.Error(), "failed to resolve redis passwords") {
		t.Fatalf("expected vault resolution error, got %v", err)
	}
}

func TestNew_VaultError_Sentinel_Fatal(t *testing.T) {
	vc := &mockVaultClient{
		enabled: true,
		kv:      &mockKVClient{err: errors.New("vault sealed")},
	}

	cfg := &Config{
		Sentinel: &config.RedisSentinelConfig{
			MasterName:        "mymaster",
			SentinelAddrs:     []string{"127.0.0.1:1"},
			PasswordVaultPath: "secret/master",
		},
	}

	_, err := New(context.Background(), cfg, testLogger(),
		WithVaultClient(vc), WithPingMode(PingBestEffort))
	if err == nil || !strings.Contains(err.Error(), "failed to resolve redis passwords") {
		t.Fatalf("expected sentinel vault resolution error through New, got %v", err)
	}
}

func TestNew_VaultDisabled_Warns(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := New(context.Background(),
		&Config{URL: "redis://" + mr.Addr(), PasswordVaultPath: "secret/redis"},
		testLogger(), WithVaultClient(&mockVaultClient{enabled: false}))
	if err != nil {
		t.Fatalf("disabled vault should not fail construction: %v", err)
	}
	defer func() { _ = client.Close() }()
}

func TestReadVaultPassword(t *testing.T) {
	vc := &mockVaultClient{
		enabled: true,
		kv: &mockKVClient{data: map[string]map[string]interface{}{
			"secret/redis": {"password": "pw"},
			"secret/empty": {"password": ""},
			"secret/wrong": {"token": "x"},
		}},
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr string
	}{
		{name: "valid", path: "secret/redis", want: "pw"},
		{name: "invalid format", path: "nopath", wantErr: "invalid vault path format"},
		{name: "empty password", path: "secret/empty", wantErr: "does not contain a valid 'password' key"},
		{name: "missing key", path: "secret/wrong", wantErr: "does not contain a valid 'password' key"},
		{name: "read error", path: "secret/missing", wantErr: "vault read failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadVaultPassword(context.Background(), vc, tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("password = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveSentinelPasswords(t *testing.T) {
	vc := &mockVaultClient{
		enabled: true,
		kv: &mockKVClient{data: map[string]map[string]interface{}{
			"secret/master":   {"password": "master-pw"},
			"secret/sentinel": {"password": "sentinel-pw"},
		}},
	}

	sentinel := &config.RedisSentinelConfig{
		MasterName:                "m",
		PasswordVaultPath:         "secret/master",
		SentinelPasswordVaultPath: "secret/sentinel",
	}

	if err := resolveSentinelPasswords(context.Background(), sentinel, vc, testLogger()); err != nil {
		t.Fatalf("resolveSentinelPasswords: %v", err)
	}
	if sentinel.Password != "master-pw" || sentinel.SentinelPassword != "sentinel-pw" {
		t.Errorf("passwords not resolved: %+v", sentinel)
	}
}

func TestResolveSentinelPasswords_Errors(t *testing.T) {
	vc := &mockVaultClient{enabled: true, kv: &mockKVClient{err: errors.New("boom")}}

	if err := resolveSentinelPasswords(context.Background(), nil, vc, testLogger()); err != nil {
		t.Fatalf("nil sentinel must not error: %v", err)
	}

	masterErr := resolveSentinelPasswords(context.Background(),
		&config.RedisSentinelConfig{PasswordVaultPath: "a/b"}, vc, testLogger())
	if masterErr == nil || !strings.Contains(masterErr.Error(), "redis master password") {
		t.Fatalf("expected master password error, got %v", masterErr)
	}

	sentinelErr := resolveSentinelPasswords(context.Background(),
		&config.RedisSentinelConfig{SentinelPasswordVaultPath: "a/b"}, vc, testLogger())
	if sentinelErr == nil || !strings.Contains(sentinelErr.Error(), "sentinel password") {
		t.Fatalf("expected sentinel password error, got %v", sentinelErr)
	}
}

func TestApplyPasswordToURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{name: "empty url", url: "", want: ""},
		{name: "no user", url: "redis://localhost:6379", want: "redis://:pw@localhost:6379"},
		{name: "existing user", url: "redis://user@localhost:6379", want: "redis://user:pw@localhost:6379"},
		{name: "invalid url", url: "://bad", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyPasswordToURL(tt.url, "pw")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("url = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHasVaultPaths(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{name: "none", cfg: &Config{}, want: false},
		{name: "standalone", cfg: &Config{PasswordVaultPath: "a/b"}, want: true},
		{name: "sentinel master", cfg: &Config{
			Sentinel: &config.RedisSentinelConfig{PasswordVaultPath: "a/b"}}, want: true},
		{name: "sentinel auth", cfg: &Config{
			Sentinel: &config.RedisSentinelConfig{SentinelPasswordVaultPath: "a/b"}}, want: true},
		{name: "sentinel without paths", cfg: &Config{
			Sentinel: &config.RedisSentinelConfig{MasterName: "m"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasVaultPaths(tt.cfg); got != tt.want {
				t.Errorf("hasVaultPaths = %v, want %v", got, tt.want)
			}
		})
	}
}
