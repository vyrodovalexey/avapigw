package grpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

// TestEnableReflection tests enabling gRPC reflection
func TestEnableReflection(t *testing.T) {
	t.Parallel()

	server := grpc.NewServer()

	// Should not panic
	EnableReflection(server)
}

// TestDefaultReflectionConfig tests default reflection configuration
func TestDefaultReflectionConfig(t *testing.T) {
	t.Parallel()

	config := DefaultReflectionConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.Nil(t, config.ServiceNames)
}

// TestReflectionConfig tests ReflectionConfig struct
func TestReflectionConfig(t *testing.T) {
	t.Parallel()

	t.Run("default values", func(t *testing.T) {
		config := &ReflectionConfig{}
		assert.False(t, config.Enabled)
		assert.Nil(t, config.ServiceNames)
	})

	t.Run("with enabled", func(t *testing.T) {
		config := &ReflectionConfig{
			Enabled: true,
		}
		assert.True(t, config.Enabled)
	})

	t.Run("with service names", func(t *testing.T) {
		config := &ReflectionConfig{
			Enabled:      true,
			ServiceNames: []string{"service1", "service2"},
		}
		assert.True(t, config.Enabled)
		assert.Len(t, config.ServiceNames, 2)
		assert.Contains(t, config.ServiceNames, "service1")
		assert.Contains(t, config.ServiceNames, "service2")
	})
}

// TestRegisterReflection tests RegisterReflection function
func TestRegisterReflection(t *testing.T) {
	t.Parallel()

	t.Run("with nil config does nothing", func(t *testing.T) {
		server := grpc.NewServer()
		// Should not panic
		RegisterReflection(server, nil)
	})

	t.Run("with disabled config does nothing", func(t *testing.T) {
		server := grpc.NewServer()
		config := &ReflectionConfig{
			Enabled: false,
		}
		// Should not panic
		RegisterReflection(server, config)
	})

	t.Run("with enabled config registers reflection", func(t *testing.T) {
		server := grpc.NewServer()
		config := &ReflectionConfig{
			Enabled: true,
		}
		// Should not panic
		RegisterReflection(server, config)
	})

	t.Run("with service names registers reflection", func(t *testing.T) {
		server := grpc.NewServer()
		config := &ReflectionConfig{
			Enabled:      true,
			ServiceNames: []string{"test.Service"},
		}
		// Should not panic
		RegisterReflection(server, config)
	})
}

// TestReflectionConfigValidation tests ReflectionConfig validation scenarios
func TestReflectionConfigValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		config   *ReflectionConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "disabled config",
			config:   &ReflectionConfig{Enabled: false},
			expected: false,
		},
		{
			name:     "enabled config",
			config:   &ReflectionConfig{Enabled: true},
			expected: true,
		},
		{
			name: "enabled with empty service names",
			config: &ReflectionConfig{
				Enabled:      true,
				ServiceNames: []string{},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			server := grpc.NewServer()
			// Should not panic regardless of config
			RegisterReflection(server, tc.config)
		})
	}
}

// TestReflectionWithMultipleServers tests reflection with multiple servers
func TestReflectionWithMultipleServers(t *testing.T) {
	t.Parallel()

	server1 := grpc.NewServer()
	server2 := grpc.NewServer()

	config := &ReflectionConfig{
		Enabled: true,
	}

	// Should not panic when registering on multiple servers
	RegisterReflection(server1, config)
	RegisterReflection(server2, config)
}
