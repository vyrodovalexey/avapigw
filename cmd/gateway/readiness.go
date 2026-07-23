package main

// Readiness dependency checks (T3.G1 / review M9).
//
// The health.Checker supports named readiness checks, but production code
// previously registered none — /ready reflected only the draining flag.
// This file registers cheap CACHED checks for the gateway's critical
// dependencies so Kubernetes can steer traffic away from a degraded pod:
//
//   - vault:    sealed/uninitialized/unreachable Vault → unhealthy
//   - backends: aggregate backend registry health (all down → unhealthy,
//               some down → degraded)
//   - redis_rate_limiter: Redis PING behind the global rate limiter
//               (fail-closed limiter + Redis down → unhealthy, because every
//               request is being rejected; fail-open → degraded)
//
// Expensive probes (Vault HTTP health, Redis PING) are evaluated by a
// background refresher and served from an atomic snapshot, so the /ready
// endpoint stays O(1) with no per-request dependency calls.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Readiness check names and refresh tuning.
const (
	// readinessCheckVault is the registered name of the Vault health check.
	readinessCheckVault = "vault"

	// readinessCheckBackends is the registered name of the backend
	// registry aggregate health check.
	readinessCheckBackends = "backends"

	// readinessCheckRedisRateLimit is the registered name of the global
	// rate limiter Redis connectivity check.
	readinessCheckRedisRateLimit = "redis_rate_limiter"

	// readinessRefreshInterval is how often cached dependency probes are
	// re-evaluated in the background.
	readinessRefreshInterval = 10 * time.Second

	// readinessProbeTimeout bounds a single dependency probe evaluation.
	readinessProbeTimeout = 5 * time.Second
)

// redisReadinessPinger is the surface the readiness check needs from a
// redis-backed rate limiter. *middleware.RedisRateLimiter satisfies it; the
// in-memory limiter does not, which cleanly disables the check.
type redisReadinessPinger interface {
	Ping(ctx context.Context) error
	IsFailOpen() bool
}

// cachedReadinessCheck evaluates an expensive dependency probe in the
// background and serves the latest result from an atomic snapshot, keeping
// the /ready endpoint free of per-request dependency calls.
type cachedReadinessCheck struct {
	name   string
	eval   func(ctx context.Context) health.Check
	last   atomic.Value // health.Check
	logger observability.Logger
}

// newCachedReadinessCheck builds the cached check and stores an initial
// synchronous evaluation so /ready never observes an empty snapshot.
func newCachedReadinessCheck(
	ctx context.Context,
	name string,
	logger observability.Logger,
	eval func(ctx context.Context) health.Check,
) *cachedReadinessCheck {
	c := &cachedReadinessCheck{name: name, eval: eval, logger: logger}
	c.refresh(ctx)
	return c
}

// refresh evaluates the probe once (bounded by readinessProbeTimeout) and
// stores the result.
func (c *cachedReadinessCheck) refresh(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, readinessProbeTimeout)
	defer cancel()

	check := c.eval(probeCtx)
	c.last.Store(check)

	if check.Status != health.StatusHealthy {
		c.logger.Debug("readiness dependency check not healthy",
			observability.String("check", c.name),
			observability.String("status", string(check.Status)),
			observability.String("message", check.Message),
		)
	}
}

// Check returns the latest cached result (health.CheckFunc compatible).
func (c *cachedReadinessCheck) Check() health.Check {
	if v, ok := c.last.Load().(health.Check); ok {
		return v
	}
	// Defensive: before the first evaluation completes the dependency state
	// is unknown; report degraded rather than blocking readiness entirely.
	return health.Check{Status: health.StatusDegraded, Message: "check not evaluated yet"}
}

// readinessRegistry owns the background refresher for all cached checks.
type readinessRegistry struct {
	checks []*cachedReadinessCheck

	// refreshInterval overrides readinessRefreshInterval when positive.
	// Production wiring leaves it zero; tests inject a short interval to
	// exercise the periodic refresh deterministically.
	refreshInterval time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// stop terminates the background refresher. Safe to call multiple times and
// on a nil registry (no checks were registered).
func (r *readinessRegistry) stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
		<-r.doneCh
	})
}

// run refreshes every cached check on a fixed interval until stopped.
func (r *readinessRegistry) run(ctx context.Context) {
	defer close(r.doneCh)

	interval := r.refreshInterval
	if interval <= 0 {
		interval = readinessRefreshInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			for _, c := range r.checks {
				c.refresh(ctx)
			}
		}
	}
}

// registerReadinessChecks wires the dependency readiness checks into the
// application health checker and starts the background refresher. It
// returns nil when no dependency needs a cached probe (pure in-memory
// deployment), so callers can skip lifecycle management.
func registerReadinessChecks(app *application, logger observability.Logger) *readinessRegistry {
	if app == nil || app.healthChecker == nil {
		return nil
	}

	// Backend aggregate health reads in-memory atomics only — cheap enough
	// to evaluate inline on every /ready request, no caching needed.
	registerBackendReadinessCheck(app.healthChecker, app.backendRegistry, app.grpcBackendRegistry)

	ctx := context.Background()
	var cached []*cachedReadinessCheck

	if check := newVaultReadinessCheck(ctx, app.vaultClient, logger); check != nil {
		app.healthChecker.RegisterCheck(readinessCheckVault, check.Check)
		cached = append(cached, check)
	}

	if check := newRedisRateLimitReadinessCheck(ctx, app.rateLimiter, logger); check != nil {
		app.healthChecker.RegisterCheck(readinessCheckRedisRateLimit, check.Check)
		cached = append(cached, check)
	}

	if len(cached) == 0 {
		logger.Info("readiness dependency checks registered",
			observability.Int("cached_checks", 0),
		)
		return nil
	}

	registry := &readinessRegistry{
		checks: cached,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go registry.run(ctx)

	logger.Info("readiness dependency checks registered",
		observability.Int("cached_checks", len(cached)),
	)
	return registry
}

// newVaultReadinessCheck builds the cached Vault health check. Returns nil
// when no enabled Vault client is configured.
func newVaultReadinessCheck(
	ctx context.Context, client vault.Client, logger observability.Logger,
) *cachedReadinessCheck {
	if client == nil || !client.IsEnabled() {
		return nil
	}

	return newCachedReadinessCheck(ctx, readinessCheckVault, logger,
		func(probeCtx context.Context) health.Check {
			return evaluateVaultHealth(probeCtx, client)
		})
}

// evaluateVaultHealth maps the Vault health status onto a readiness check
// result: unreachable/sealed/uninitialized → unhealthy, standby → healthy
// (standby nodes serve reads and forward writes).
func evaluateVaultHealth(ctx context.Context, client vault.Client) health.Check {
	status, err := client.Health(ctx)
	switch {
	case err != nil:
		return health.Check{
			Status:  health.StatusUnhealthy,
			Message: fmt.Sprintf("vault health check failed: %v", err),
		}
	case status == nil:
		// Defensive: a nil status without an error carries no signal
		// (possible with fake clients); report degraded, not a panic.
		return health.Check{Status: health.StatusDegraded, Message: "vault health status unavailable"}
	case status.Sealed:
		return health.Check{Status: health.StatusUnhealthy, Message: "vault is sealed"}
	case !status.Initialized:
		return health.Check{Status: health.StatusUnhealthy, Message: "vault is not initialized"}
	default:
		return health.Check{Status: health.StatusHealthy}
	}
}

// newRedisRateLimitReadinessCheck builds the cached Redis connectivity
// check for the global rate limiter. Returns nil when the active limiter is
// not redis-backed.
func newRedisRateLimitReadinessCheck(
	ctx context.Context, limiter any, logger observability.Logger,
) *cachedReadinessCheck {
	pinger, ok := limiter.(redisReadinessPinger)
	if !ok {
		return nil
	}

	return newCachedReadinessCheck(ctx, readinessCheckRedisRateLimit, logger,
		func(probeCtx context.Context) health.Check {
			return evaluateRedisRateLimitHealth(probeCtx, pinger)
		})
}

// evaluateRedisRateLimitHealth maps limiter Redis connectivity onto a
// readiness result honoring the failure policy: a fail-closed limiter with
// Redis down rejects every request (unhealthy), a fail-open one degrades to
// unlimited traffic (degraded).
func evaluateRedisRateLimitHealth(ctx context.Context, pinger redisReadinessPinger) health.Check {
	err := pinger.Ping(ctx)
	if err == nil {
		return health.Check{Status: health.StatusHealthy}
	}

	status := health.StatusUnhealthy
	if pinger.IsFailOpen() {
		status = health.StatusDegraded
	}
	return health.Check{
		Status:  status,
		Message: fmt.Sprintf("rate limiter redis unreachable: %v", err),
	}
}

// registerBackendReadinessCheck registers the aggregate backend health
// check. It evaluates in-memory status atomics only (no network I/O), so it
// runs inline per /ready request.
func registerBackendReadinessCheck(
	checker *health.Checker, registries ...*backend.Registry,
) {
	var all []*backend.Registry
	for _, r := range registries {
		if r != nil {
			all = append(all, r)
		}
	}
	if len(all) == 0 {
		return
	}

	checker.RegisterCheck(readinessCheckBackends, func() health.Check {
		return evaluateBackendHealth(all)
	})
}

// evaluateBackendHealth aggregates backend statuses across the given
// registries: no backends → healthy (nothing to route to is a config
// choice), all unhealthy → unhealthy, some unhealthy → degraded.
func evaluateBackendHealth(registries []*backend.Registry) health.Check {
	total := 0
	unhealthy := 0
	for _, reg := range registries {
		for _, b := range reg.GetAll() {
			total++
			if b.Status() == backend.StatusUnhealthy {
				unhealthy++
			}
		}
	}

	switch {
	case total == 0 || unhealthy == 0:
		return health.Check{Status: health.StatusHealthy}
	case unhealthy == total:
		return health.Check{
			Status:  health.StatusUnhealthy,
			Message: fmt.Sprintf("all %d backends unhealthy", total),
		}
	default:
		return health.Check{
			Status:  health.StatusDegraded,
			Message: fmt.Sprintf("%d of %d backends unhealthy", unhealthy, total),
		}
	}
}
