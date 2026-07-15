package grpcadapter

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	grpcproxy "github.com/vyrodovalexey/avapigw/internal/grpc/proxy"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// authHeaderKey is the canonical gRPC metadata key carrying credentials.
const authHeaderKey = "authorization"

// ConnPool is the minimal subset of the gRPC proxy connection pool required by
// the aggregate invoker. It is satisfied by *grpcproxy.ConnectionPool and lets
// the engine reuse the same pooled, per-target (m)TLS-aware client connections
// used by single-destination proxying.
type ConnPool interface {
	// GetWithTLS returns a pooled connection to target, using tlsConfig when
	// non-nil (delegating to plaintext Get when nil).
	GetWithTLS(ctx context.Context, target string, tlsConfig *tls.Config) (*grpc.ClientConn, error)
}

// ensure *grpcproxy.ConnectionPool satisfies ConnPool at compile time.
var _ ConnPool = (*grpcproxy.ConnectionPool)(nil)

// Invoker is an aggregate.Invoker backed by the gRPC proxy connection pool. It
// performs a raw, codec-transparent grpc.ClientConn.Invoke per target so request
// and response payloads are passed as opaque bytes (grpcproxy.Frame). Per-target
// mTLS is honored via the pool's GetWithTLS; per-target authentication is applied
// as outgoing gRPC metadata.
type Invoker struct {
	pool       ConnPool
	logger     observability.Logger
	fullMethod string
	tlsCache   sync.Map // target name -> *tlsCacheEntry (at most one per target)
}

// tlsCacheEntry pairs a built *tls.Config with the fingerprint of the
// TLS-relevant configuration it was built from. Keeping exactly one entry per
// target name — replaced whenever the fingerprint changes — bounds the cache
// to the number of configured targets while still invalidating stale entries
// after route/backend config reloads.
type tlsCacheEntry struct {
	fingerprint string
	cfg         *tls.Config
}

// InvokerOption configures the gRPC aggregate Invoker.
type InvokerOption func(*Invoker)

// WithInvokerLogger sets the structured logger.
func WithInvokerLogger(logger observability.Logger) InvokerOption {
	return func(i *Invoker) {
		if logger != nil {
			i.logger = logger
		}
	}
}

// NewInvoker creates a gRPC aggregate Invoker bound to a connection pool and the
// full gRPC method being aggregated (e.g. "/pkg.Svc/Method"). The same method is
// invoked on every target, mirroring transparent proxy semantics.
func NewInvoker(pool ConnPool, fullMethod string, opts ...InvokerOption) *Invoker {
	i := &Invoker{
		pool:       pool,
		logger:     observability.NopLogger(),
		fullMethod: fullMethod,
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// Invoke implements aggregate.Invoker. It dials the target through the pool,
// applies per-target auth metadata, and performs a raw unary invocation using the
// proxy's transparent Frame codec.
func (i *Invoker) Invoke(
	ctx context.Context,
	target aggregate.Target,
	req *aggregate.Request,
) (*aggregate.Response, error) {
	tlsCfg, err := i.tlsConfigFor(&target)
	if err != nil {
		return &aggregate.Response{Target: target.Name, Err: err}, err
	}

	addr := targetAddress(&target)
	conn, err := i.pool.GetWithTLS(ctx, addr, tlsCfg)
	if err != nil {
		wrapped := fmt.Errorf("aggregate gRPC dial %s: %w", addr, err)
		return &aggregate.Response{Target: target.Name, Err: wrapped}, wrapped
	}

	outCtx := i.outgoingContext(ctx, req, &target)

	in := grpcproxy.NewFrame(req.Body)
	out := grpcproxy.NewFrame(nil)
	if invErr := conn.Invoke(outCtx, i.fullMethod, in, out); invErr != nil {
		// gRPC application/transport errors are reported as per-target failures
		// via Response.Err (not as the transport-level second return value) so
		// the aggregate engine attributes them to this target and applies its
		// FailMode/retry/backoff policy rather than aborting the whole fan-out.
		//nolint:nilerr // intentional: per-target failures travel via Response.Err
		return &aggregate.Response{Target: target.Name, Err: invErr}, nil
	}

	return &aggregate.Response{
		Target:      target.Name,
		StatusCode:  0, // 0 == gRPC OK
		Body:        out.Payload(),
		ContentType: "application/grpc",
	}, nil
}

// outgoingContext builds the per-target outgoing context, forwarding the inbound
// request headers/metadata and injecting per-target authentication.
func (i *Invoker) outgoingContext(
	ctx context.Context, req *aggregate.Request, target *aggregate.Target,
) context.Context {
	return metadata.NewOutgoingContext(ctx, outgoingMetadata(req, target))
}

// outgoingMetadata builds the outgoing gRPC metadata for a target. Keys are
// normalized to lowercase via metadata.MD.Append/Set as required by the gRPC
// metadata contract; writing mixed-case keys directly into the map would leave
// entries that readers expecting lowercase keys silently miss or duplicate.
func outgoingMetadata(req *aggregate.Request, target *aggregate.Target) metadata.MD {
	md := metadata.MD{}
	for k, values := range req.Headers {
		md.Append(k, values...)
	}
	if key, value := authHeader(target.Auth); value != "" {
		md.Set(key, value)
	}
	return md
}

// tlsConfigFor returns (and caches) the *tls.Config for a target, built from its
// per-target BackendTLSConfig (including mTLS). Returns nil when TLS is disabled.
//
// The cache is keyed by target name but validated against a deterministic
// fingerprint of the TLS-relevant config, so a route/backend reload that
// changes the TLS settings naturally misses the stale entry and rebuilds it in
// place (the cache never holds more than one entry per target name).
func (i *Invoker) tlsConfigFor(target *aggregate.Target) (*tls.Config, error) {
	if target.TLS == nil || !target.TLS.Enabled {
		return nil, nil
	}
	fingerprint, err := tlsConfigFingerprint(target.TLS)
	if err != nil {
		return nil, fmt.Errorf("aggregate gRPC TLS fingerprint for target %s: %w", target.Name, err)
	}
	if cached, ok := i.tlsCache.Load(target.Name); ok {
		if entry, entryOK := cached.(*tlsCacheEntry); entryOK && entry.fingerprint == fingerprint {
			return entry.cfg, nil
		}
		// Fingerprint mismatch: the target's TLS config changed (config
		// reload); fall through to rebuild and replace the stale entry.
	}

	builder := backend.NewTLSConfigBuilder(target.TLS, backend.WithTLSLogger(i.logger))
	built, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("aggregate gRPC TLS for target %s: %w", target.Name, err)
	}
	var cfg *tls.Config
	if built != nil {
		cfg = built.Clone()
		// gRPC requires h2 ALPN; ensure it is advertised.
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"h2"}
		}
	}
	// Store replaces any stale entry for this name, bounding the cache to one
	// entry per target. Concurrent rebuilds are benign: both goroutines build
	// from the same immutable config and the last stored entry wins.
	i.tlsCache.Store(target.Name, &tlsCacheEntry{fingerprint: fingerprint, cfg: cfg})
	return cfg, nil
}

// tlsConfigFingerprint returns a deterministic hash of the TLS-relevant target
// configuration. JSON marshaling of the config struct is deterministic (fixed
// struct field order, no map fields), so identical configs always produce the
// same fingerprint while any TLS config change yields a new one.
func tlsConfigFingerprint(cfg *config.BackendTLSConfig) (string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// targetAddress builds the host:port dial address for a target.
func targetAddress(target *aggregate.Target) string {
	if target.Port > 0 {
		return net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	}
	return target.Host
}

// authHeader resolves a static credential (metadata key + value) for a target
// from its per-target auth config. Dynamic OIDC/Vault token sources are resolved
// by upstream middleware; this adapter only forwards statically-provided
// credentials, mirroring the REST invoker. It returns ("", "") when no
// credential applies.
func authHeader(auth *config.BackendAuthConfig) (key, value string) {
	if auth == nil {
		return "", ""
	}
	switch auth.Type {
	case "basic":
		return authHeaderKey, basicAuthHeader(auth.Basic)
	case "jwt":
		return jwtAuthHeader(auth.JWT)
	default:
		// No-op: unauthenticated targets and unknown types pass through without
		// injecting credentials.
		return "", ""
	}
}

// basicAuthHeader builds an HTTP Basic credential value.
func basicAuthHeader(basic *config.BackendBasicAuthConfig) string {
	if basic == nil || !basic.Enabled || basic.Username == "" {
		return ""
	}
	creds := base64.StdEncoding.EncodeToString([]byte(basic.Username + ":" + basic.Password))
	return "Basic " + creds
}

// jwtAuthHeader builds a static bearer-token credential as a (metadata key,
// value) pair, honoring a custom header name/prefix when configured.
func jwtAuthHeader(jwt *config.BackendJWTAuthConfig) (key, value string) {
	if jwt == nil || !jwt.Enabled || jwt.StaticToken == "" {
		return "", ""
	}
	header := jwt.HeaderName
	if header == "" {
		header = authHeaderKey
	}
	prefix := jwt.HeaderPrefix
	if prefix == "" {
		prefix = "Bearer"
	}
	return strings.ToLower(header), prefix + " " + jwt.StaticToken
}
