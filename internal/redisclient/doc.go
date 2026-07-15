// Package redisclient provides shared construction of go-redis clients for
// gateway subsystems that need a Redis connection (standalone or Sentinel).
//
// It centralizes the concerns every Redis-backed subsystem shares:
//
//   - standalone (URL) vs Sentinel (failover) client construction;
//   - Vault-based password resolution for the Redis master and Sentinel;
//   - initial connectivity checks with exponential-backoff retry;
//   - pool sizing, dial/read/write timeouts and TLS settings.
//
// The distributed rate limiter (internal/middleware) builds its clients
// through this package. The route cache (internal/cache) predates it and
// still constructs clients internally; migrating it here is a planned
// follow-up that must preserve its externally observable error messages.
package redisclient
