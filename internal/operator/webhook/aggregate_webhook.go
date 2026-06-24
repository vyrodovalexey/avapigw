// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"fmt"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// Aggregate validation constants.
const (
	// MinAggregateTargets is the minimum number of fan-out targets.
	MinAggregateTargets = 1

	// MaxAggregateMaxParallel bounds the maxParallel field.
	MaxAggregateMaxParallel = 1024

	failModeAll    = "all"
	failModeAny    = "any"
	failModeQuorum = "quorum"

	mergeStrategyDeep    = "deep"
	mergeStrategyShallow = "shallow"
	mergeStrategyReplace = "replace"

	spoolBackendMemory = "memory"
	spoolBackendRedis  = "redis"

	// Backend authentication type values.
	authTypeJWT   = "jwt"
	authTypeBasic = "basic"
	authTypeMTLS  = "mtls"
)

// validateAggregate validates an aggregate (fan-out) configuration.
//
// streaming indicates the owning route is a pure-streaming protocol (e.g. a
// gRPC streaming route); merge-on-pure-streaming is rejected.
func validateAggregate(cfg *avapigwv1alpha1.AggregateConfig, streaming bool) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	if len(cfg.Targets) < MinAggregateTargets {
		return fmt.Errorf("aggregate: at least %d target is required", MinAggregateTargets)
	}

	if err := validateAggregateFailMode(cfg); err != nil {
		return err
	}

	if cfg.MaxParallel < 0 || cfg.MaxParallel > MaxAggregateMaxParallel {
		return fmt.Errorf("aggregate: maxParallel must be between 0 and %d", MaxAggregateMaxParallel)
	}

	if err := validateAggregateTargets(cfg.Targets); err != nil {
		return err
	}

	if err := validateAggregateMerge(cfg.Merge, streaming); err != nil {
		return err
	}

	return validateAggregateSpool(cfg.Spool)
}

// validateAggregateFailMode validates the failMode and quorumCount fields.
func validateAggregateFailMode(cfg *avapigwv1alpha1.AggregateConfig) error {
	switch cfg.FailMode {
	case "", failModeAll, failModeAny, failModeQuorum:
	default:
		return fmt.Errorf("aggregate: invalid failMode %q (must be all, any or quorum)", cfg.FailMode)
	}
	if cfg.QuorumCount < 0 {
		return fmt.Errorf("aggregate: quorumCount must be non-negative")
	}
	if cfg.FailMode == failModeQuorum && cfg.QuorumCount > len(cfg.Targets) {
		return fmt.Errorf("aggregate: quorumCount %d exceeds target count %d", cfg.QuorumCount, len(cfg.Targets))
	}
	return nil
}

// validateAggregateTargets validates each fan-out target and uniqueness of names.
func validateAggregateTargets(targets []avapigwv1alpha1.AggregateTarget) error {
	seen := make(map[string]struct{}, len(targets))
	for i := range targets {
		t := &targets[i]
		if t.Name == "" {
			return fmt.Errorf("aggregate: targets[%d].name is required", i)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("aggregate: duplicate target name %q", t.Name)
		}
		seen[t.Name] = struct{}{}

		if t.Destination.Host == "" {
			return fmt.Errorf("aggregate: targets[%d].destination.host is required", i)
		}
		if t.Destination.Port < MinPort || t.Destination.Port > MaxPort {
			return fmt.Errorf("aggregate: targets[%d].destination.port must be between %d and %d", i, MinPort, MaxPort)
		}
		if t.Timeout != "" {
			if err := validateDuration(string(t.Timeout)); err != nil {
				return fmt.Errorf("aggregate: targets[%d].timeout: %w", i, err)
			}
		}
		if err := validateAggregateTargetAuth(i, t); err != nil {
			return err
		}
	}
	return nil
}

// validateAggregateTargetAuth validates per-target authentication references.
func validateAggregateTargetAuth(i int, t *avapigwv1alpha1.AggregateTarget) error {
	if t.Authentication == nil {
		return nil
	}
	switch t.Authentication.Type {
	case "", authTypeJWT, authTypeBasic, authTypeMTLS:
		return nil
	default:
		return fmt.Errorf(
			"aggregate: targets[%d].authentication.type %q is invalid (must be jwt, basic or mtls)",
			i, t.Authentication.Type,
		)
	}
}

// validateAggregateMerge validates merge options and rejects merge on pure
// streaming routes.
func validateAggregateMerge(merge *avapigwv1alpha1.MergeOptions, streaming bool) error {
	if merge == nil || !merge.Enabled {
		return nil
	}
	if streaming {
		return fmt.Errorf("aggregate: merge cannot be enabled on a pure-streaming route")
	}
	switch merge.Strategy {
	case "", mergeStrategyDeep, mergeStrategyShallow, mergeStrategyReplace:
		return nil
	default:
		return fmt.Errorf("aggregate: invalid merge.strategy %q (must be deep, shallow or replace)", merge.Strategy)
	}
}

// validateAggregateSpool validates spool options, requiring a Redis reference
// when the redis backend is selected.
func validateAggregateSpool(spool *avapigwv1alpha1.SpoolOptions) error {
	if spool == nil || !spool.Enabled {
		return nil
	}
	if spool.ThresholdBytes < 0 {
		return fmt.Errorf("aggregate: spool.thresholdBytes must be non-negative")
	}
	switch spool.Backend {
	case "", spoolBackendMemory:
		return nil
	case spoolBackendRedis:
		return validateAggregateSpoolRedis(spool.RedisRef)
	default:
		return fmt.Errorf("aggregate: invalid spool.backend %q (must be memory or redis)", spool.Backend)
	}
}

// validateAggregateSpoolRedis validates the Redis reference for redis spooling.
func validateAggregateSpoolRedis(ref *avapigwv1alpha1.AggregateRedisRef) error {
	if ref == nil {
		return fmt.Errorf("aggregate: spool.redisRef is required when spool.backend is redis")
	}
	hasAddr := ref.Address != ""
	hasSentinel := ref.Sentinel != nil
	if !hasAddr && !hasSentinel {
		return fmt.Errorf("aggregate: spool.redisRef requires either address or sentinel")
	}
	if hasAddr && hasSentinel {
		return fmt.Errorf("aggregate: spool.redisRef.address and sentinel are mutually exclusive")
	}
	return nil
}
