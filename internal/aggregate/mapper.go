package aggregate

import (
	"github.com/vyrodovalexey/avapigw/internal/config"
)

// FromConfig converts a config.AggregateConfig into the runtime Config consumed
// by the engine. It returns nil when the input is nil or disabled. Defaults are
// applied so the resulting Config is directly usable by the engine.
//
// This mapping layer keeps the aggregate package decoupled from api/v1alpha1 and
// the operator: CRD-derived configuration is first converted to
// config.AggregateConfig (by the operator/config loader) and then mapped here.
func FromConfig(cfg *config.AggregateConfig) *Config {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	out := &Config{
		Enabled:         true,
		FailMode:        FailMode(cfg.GetFailMode()),
		QuorumCount:     cfg.QuorumCount,
		MaxParallel:     cfg.GetMaxParallel(),
		PerMessageMerge: cfg.PerMessageMerge,
		Targets:         mapTargets(cfg.Targets),
	}

	out.Merge = mapMerge(cfg.Merge)
	out.Spool = mapSpool(cfg)

	return out
}

// mapTargets converts config targets into runtime targets, applying per-target
// timeout defaults.
func mapTargets(in []config.AggregateTarget) []Target {
	if len(in) == 0 {
		return nil
	}
	targets := make([]Target, 0, len(in))
	for i := range in {
		t := &in[i]
		timeout := t.Timeout.Duration()
		if timeout <= 0 {
			timeout = DefaultTargetTimeout
		}
		targets = append(targets, Target{
			Name:    t.Name,
			Host:    t.Destination.Host,
			Port:    t.Destination.Port,
			Timeout: timeout,
			Retries: t.Retries,
			TLS:     t.TLS,
			Auth:    t.Authentication,
		})
	}
	return targets
}

// mapMerge converts config merge options into runtime merge options.
func mapMerge(in *config.MergeOptions) *MergeOptions {
	if in == nil {
		return nil
	}
	strategy := in.Strategy
	if in.Enabled && strategy == "" {
		strategy = config.MergeStrategyDeep
	}
	return &MergeOptions{
		Enabled:   in.Enabled,
		Strategy:  strategy,
		TimeField: in.TimeField,
		KeyField:  in.KeyField,
		Limit:     in.Limit,
	}
}

// mapSpool converts config spool options into runtime spool options, applying
// ENV-aware threshold resolution.
func mapSpool(cfg *config.AggregateConfig) *SpoolOptions {
	in := cfg.Spool
	if in == nil {
		return nil
	}
	backend := in.Backend
	if backend == "" {
		backend = SpoolBackendMemory
	}
	ttl := in.TTL.Duration()
	if ttl <= 0 {
		ttl = DefaultSpoolTTL
	}
	return &SpoolOptions{
		Enabled:        in.Enabled,
		Backend:        backend,
		ThresholdBytes: cfg.GetSpoolThresholdBytes(),
		TTL:            ttl,
	}
}
