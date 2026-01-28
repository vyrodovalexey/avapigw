package config

// ObservabilityConfig represents observability configuration.
type ObservabilityConfig struct {
	Metrics *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Tracing *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
	Logging *LoggingConfig `yaml:"logging,omitempty" json:"logging,omitempty"`
}

// MetricsConfig represents metrics configuration.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// TracingConfig represents tracing configuration.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled" json:"enabled"`
	SamplingRate float64 `yaml:"samplingRate,omitempty" json:"samplingRate,omitempty"`
	OTLPEndpoint string  `yaml:"otlpEndpoint,omitempty" json:"otlpEndpoint,omitempty"`
	ServiceName  string  `yaml:"serviceName,omitempty" json:"serviceName,omitempty"`
}

// LoggingConfig represents logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level,omitempty" json:"level,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
}
