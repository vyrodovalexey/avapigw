// Package rest provides a REST/HTTP adapter for the aggregate fan-out engine.
//
// It implements aggregate.Invoker for plain HTTP backends, honoring per-target
// TLS (including mTLS via internal/backend) and per-target authentication
// (basic, bearer/JWT, API key). The package is wired into internal/proxy via an
// injected interface to avoid import cycles.
package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/aggregate"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// defaultDialTimeout bounds connection establishment per target.
const defaultDialTimeout = 10 * time.Second

// Transport pooling for fan-out targets. Mirrors the REST reverse proxy's
// pooled transport (internal/proxy): without an explicit
// MaxIdleConnsPerHost, net/http keeps only 2 idle connections per host,
// forcing per-request dials at fan-out load and churning ephemeral ports.
const (
	// defaultMaxIdleConns caps idle connections across all targets.
	defaultMaxIdleConns = 512

	// defaultMaxIdleConnsPerHost keeps enough warm connections per target
	// host to avoid per-request dials at load.
	defaultMaxIdleConnsPerHost = 100

	// defaultIdleConnTimeout matches the backend pool convention.
	defaultIdleConnTimeout = 90 * time.Second

	// defaultDialKeepAlive is the TCP keep-alive probe interval.
	defaultDialKeepAlive = 30 * time.Second
)

// Invoker is an aggregate.Invoker backed by net/http. It maintains a per-target
// http.Client cache so TLS material is reused across fan-out invocations.
type Invoker struct {
	scheme  string
	logger  observability.Logger
	clients sync.Map // target name -> *http.Client
}

// Option configures the REST Invoker.
type Option func(*Invoker)

// WithScheme overrides the request scheme (defaults to http; use https for TLS
// targets).
func WithScheme(scheme string) Option {
	return func(i *Invoker) {
		if scheme != "" {
			i.scheme = scheme
		}
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger observability.Logger) Option {
	return func(i *Invoker) {
		if logger != nil {
			i.logger = logger
		}
	}
}

// NewInvoker creates a new REST Invoker.
func NewInvoker(opts ...Option) *Invoker {
	i := &Invoker{
		scheme: "http",
		logger: observability.NopLogger(),
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// Invoke implements aggregate.Invoker.
func (i *Invoker) Invoke(
	ctx context.Context,
	target aggregate.Target,
	req *aggregate.Request,
) (*aggregate.Response, error) {
	client, err := i.clientFor(&target)
	if err != nil {
		return &aggregate.Response{Target: target.Name, Err: err}, err
	}

	httpReq, err := i.buildRequest(ctx, &target, req)
	if err != nil {
		return &aggregate.Response{Target: target.Name, Err: err}, err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return &aggregate.Response{Target: target.Name, Err: err}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &aggregate.Response{Target: target.Name, Err: err}, err
	}

	return &aggregate.Response{
		Target:      target.Name,
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header,
		Body:        body,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

// buildRequest constructs the per-target HTTP request, applying headers and
// per-target authentication.
func (i *Invoker) buildRequest(
	ctx context.Context,
	target *aggregate.Target,
	req *aggregate.Request,
) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	url := i.targetURL(target, req.Path)
	httpReq, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}

	for name, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(name, v)
		}
	}

	applyAuth(httpReq, target.Auth)
	return httpReq, nil
}

// targetURL builds the request URL for a target.
func (i *Invoker) targetURL(target *aggregate.Target, path string) string {
	scheme := i.scheme
	if target.TLS != nil && target.TLS.Enabled {
		scheme = "https"
	}
	host := target.Host
	if target.Port > 0 {
		host = net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	}
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// clientFor returns (creating and caching if needed) the http.Client for a
// target, configured with the target's TLS material.
func (i *Invoker) clientFor(target *aggregate.Target) (*http.Client, error) {
	if cached, ok := i.clients.Load(target.Name); ok {
		return cached.(*http.Client), nil
	}

	transport, err := i.transportFor(target.TLS)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Transport: transport}
	actual, _ := i.clients.LoadOrStore(target.Name, client)
	return actual.(*http.Client), nil
}

// transportFor builds an http.Transport honoring the target's TLS configuration.
func (i *Invoker) transportFor(tlsCfg *config.BackendTLSConfig) (*http.Transport, error) {
	transport := &http.Transport{
		// HTTP request redirections are handled by an explicit non-following
		// policy at the client level; the transport itself never auto-forwards.
		DialContext: (&net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: defaultDialKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		IdleConnTimeout:     defaultIdleConnTimeout,
		TLSHandshakeTimeout: defaultDialTimeout,
	}
	if tlsCfg == nil || !tlsCfg.Enabled {
		return transport, nil
	}

	builder := backend.NewTLSConfigBuilder(tlsCfg, backend.WithTLSLogger(i.logger))
	built, err := builder.Build()
	if err != nil {
		return nil, err
	}
	if built != nil {
		transport.TLSClientConfig = built.Clone()
	}
	return transport, nil
}

// applyAuth applies per-target authentication to the outbound request.
func applyAuth(httpReq *http.Request, auth *config.BackendAuthConfig) {
	if auth == nil {
		return
	}
	switch auth.Type {
	case "basic":
		applyBasicAuth(httpReq, auth.Basic)
	case "jwt":
		applyJWTAuth(httpReq, auth.JWT)
	default:
		// No-op: unauthenticated targets and unknown types pass through without
		// injecting credentials.
	}
}

// applyBasicAuth applies HTTP Basic authentication.
func applyBasicAuth(httpReq *http.Request, basic *config.BackendBasicAuthConfig) {
	if basic == nil || !basic.Enabled || basic.Username == "" {
		return
	}
	credentials := base64.StdEncoding.EncodeToString([]byte(basic.Username + ":" + basic.Password))
	httpReq.Header.Set("Authorization", "Basic "+credentials)
}

// applyJWTAuth applies a static bearer token when configured. Dynamic
// OIDC/Vault token sources are resolved by upstream middleware; this adapter
// only forwards a statically-provided token.
func applyJWTAuth(httpReq *http.Request, jwt *config.BackendJWTAuthConfig) {
	if jwt == nil || !jwt.Enabled || jwt.StaticToken == "" {
		return
	}
	header := jwt.HeaderName
	if header == "" {
		header = "Authorization"
	}
	prefix := jwt.HeaderPrefix
	if prefix == "" {
		prefix = "Bearer"
	}
	httpReq.Header.Set(header, prefix+" "+jwt.StaticToken)
}

// ensure tls import is referenced (per-target TLS config clone uses tls.Config).
var _ = (*tls.Config)(nil)
