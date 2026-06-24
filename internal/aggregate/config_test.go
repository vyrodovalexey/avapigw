package aggregate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_EffectiveMaxParallel(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want int
	}{
		{
			name: "default when unset",
			cfg:  &Config{Targets: targets("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")},
			want: DefaultMaxParallel,
		},
		{
			name: "clamped to target count",
			cfg:  &Config{MaxParallel: 100, Targets: targets("a", "b")},
			want: 2,
		},
		{
			name: "explicit within bounds",
			cfg:  &Config{MaxParallel: 3, Targets: targets("a", "b", "c", "d", "e")},
			want: 3,
		},
		{
			name: "negative falls to default then clamps",
			cfg:  &Config{MaxParallel: -5, Targets: targets("a", "b")},
			want: 2,
		},
		{
			name: "no targets returns configured",
			cfg:  &Config{MaxParallel: 4},
			want: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.EffectiveMaxParallel())
		})
	}
}

func TestConfig_SuccessThreshold(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want int
	}{
		{"any needs 1", &Config{FailMode: FailModeAny, Targets: targets("a", "b", "c")}, 1},
		{"all needs n", &Config{FailMode: FailModeAll, Targets: targets("a", "b", "c")}, 3},
		{"quorum majority of 3", &Config{FailMode: FailModeQuorum, Targets: targets("a", "b", "c")}, 2},
		{"quorum majority of 4", &Config{FailMode: FailModeQuorum, Targets: targets("a", "b", "c", "d")}, 3},
		{"quorum explicit count", &Config{FailMode: FailModeQuorum, QuorumCount: 2, Targets: targets("a", "b", "c", "d")}, 2},
		{"unknown defaults to all", &Config{FailMode: "weird", Targets: targets("a", "b")}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.cfg.successThreshold())
		})
	}
}
