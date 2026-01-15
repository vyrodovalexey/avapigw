package backend

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewURLValidator(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("with default config", func(t *testing.T) {
		v, err := NewURLValidator(nil, logger)
		require.NoError(t, err)
		assert.NotNil(t, v)
		assert.True(t, v.config.BlockPrivateIPs)
		assert.True(t, v.config.BlockLoopback)
		assert.True(t, v.config.BlockLinkLocal)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                true,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)
		assert.NotNil(t, v)
		assert.False(t, v.config.BlockPrivateIPs)
		assert.True(t, v.config.BlockLoopback)
	})

	t.Run("with invalid allowed CIDR", func(t *testing.T) {
		config := &URLValidatorConfig{
			AllowedCIDRs: []string{"invalid-cidr"},
		}
		_, err := NewURLValidator(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse allowed CIDR")
	})

	t.Run("with invalid blocked CIDR", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockedCIDRs: []string{"invalid-cidr"},
		}
		_, err := NewURLValidator(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse blocked CIDR")
	})

	t.Run("with nil logger", func(t *testing.T) {
		v, err := NewURLValidator(nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, v)
	})
}

func TestURLValidator_ValidateURL_Scheme(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("allows http scheme", func(t *testing.T) {
		config := &URLValidatorConfig{
			AllowedSchemes:               []string{"http", "https"},
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://example.com")
		assert.NoError(t, err)
	})

	t.Run("allows https scheme", func(t *testing.T) {
		config := &URLValidatorConfig{
			AllowedSchemes:               []string{"http", "https"},
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("https://example.com")
		assert.NoError(t, err)
	})

	t.Run("blocks ftp scheme", func(t *testing.T) {
		config := &URLValidatorConfig{
			AllowedSchemes:               []string{"http", "https"},
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("ftp://example.com")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidScheme))
	})

	t.Run("blocks file scheme", func(t *testing.T) {
		config := &URLValidatorConfig{
			AllowedSchemes:               []string{"http", "https"},
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("file:///etc/passwd")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidScheme))
	})
}

func TestURLValidator_ValidateURL_PrivateIPs(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks 10.x.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://10.0.0.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPrivateIPBlocked))
	})

	t.Run("blocks 172.16.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://172.16.0.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPrivateIPBlocked))
	})

	t.Run("blocks 172.31.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://172.31.255.255:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPrivateIPBlocked))
	})

	t.Run("blocks 192.168.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://192.168.1.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrPrivateIPBlocked))
	})

	t.Run("allows private IPs when disabled", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://192.168.1.1:8080")
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateURL_Loopback(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks 127.0.0.1", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://127.0.0.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrLoopbackBlocked))
	})

	t.Run("blocks localhost via DNS", func(t *testing.T) {
		config := DefaultURLValidatorConfig()
		config.DNSResolutionTimeout = 1 * time.Second
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://localhost:8080")
		assert.Error(t, err)
		// localhost resolves to 127.0.0.1, which is blocked
	})

	t.Run("blocks 127.x.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://127.0.0.2:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrLoopbackBlocked))
	})

	t.Run("blocks IPv6 loopback", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://[::1]:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrLoopbackBlocked))
	})

	t.Run("allows loopback when disabled", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://127.0.0.1:8080")
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateURL_LinkLocal(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks 169.254.x.x range", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://169.254.1.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrLinkLocalBlocked))
	})

	t.Run("allows link-local when disabled", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://169.254.1.1:8080")
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateURL_AllowedCIDRs(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("allows IP in allowed CIDR despite being private", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			AllowedCIDRs:                 []string{"10.0.0.0/24"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// 10.0.0.1 is in allowed CIDR, should pass
		err = v.ValidateURL("http://10.0.0.1:8080")
		assert.NoError(t, err)

		// 10.0.1.1 is NOT in allowed CIDR, should fail
		err = v.ValidateURL("http://10.0.1.1:8080")
		assert.Error(t, err)
	})
}

func TestURLValidator_ValidateURL_BlockedCIDRs(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks IP in blocked CIDR", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			BlockedCIDRs:                 []string{"203.0.113.0/24"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://203.0.113.1:8080")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrBlockedCIDR))
	})
}

func TestURLValidator_ValidateURL_AllowedHosts(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("allows explicitly allowed host", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			AllowedHosts:                 []string{"internal.example.com"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://internal.example.com:8080")
		assert.NoError(t, err)
	})

	t.Run("allowed host is case insensitive", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			AllowedHosts:                 []string{"Internal.Example.COM"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://internal.example.com:8080")
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateURL_BlockedHosts(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks explicitly blocked host", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			BlockedHosts:                 []string{"malicious.example.com"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http://malicious.example.com:8080")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blocked")
	})
}

func TestURLValidator_ValidateURL_EmptyHost(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks empty host", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		err = v.ValidateURL("http:///path")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrEmptyHost))
	})
}

func TestURLValidator_ValidateURL_InvalidURL(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("blocks invalid URL", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.ValidateURL("://invalid")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidURL))
	})
}

func TestURLValidator_ValidateURL_PublicIPs(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("allows public IP addresses", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Google's public DNS
		err = v.ValidateURL("http://8.8.8.8:80")
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateEndpoint(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("validates endpoint address and port", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Should block private IP
		err = v.ValidateEndpoint("192.168.1.1", 8080)
		assert.Error(t, err)

		// Should allow public IP
		err = v.ValidateEndpoint("8.8.8.8", 80)
		assert.NoError(t, err)
	})
}

func TestURLValidator_ValidateURLWithContext(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("respects context cancellation", func(t *testing.T) {
		config := DefaultURLValidatorConfig()
		config.EnableDNSRebindingProtection = true
		config.DNSResolutionTimeout = 5 * time.Second
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// This should fail due to cancelled context during DNS resolution
		err = v.ValidateURLWithContext(ctx, "http://example.com:8080")
		// The error might be context cancelled or DNS resolution failed
		assert.Error(t, err)
	})
}

func TestURLValidator_DynamicHostManagement(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("add and remove allowed hosts", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Initially not allowed
		assert.False(t, v.isAllowedHost("dynamic.example.com"))

		// Add to allowed
		v.AddAllowedHost("dynamic.example.com")
		assert.True(t, v.isAllowedHost("dynamic.example.com"))

		// Remove from allowed
		v.RemoveAllowedHost("dynamic.example.com")
		assert.False(t, v.isAllowedHost("dynamic.example.com"))
	})

	t.Run("add and remove blocked hosts", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Initially not blocked
		assert.False(t, v.isBlockedHost("dynamic.example.com"))

		// Add to blocked
		v.AddBlockedHost("dynamic.example.com")
		assert.True(t, v.isBlockedHost("dynamic.example.com"))

		// Remove from blocked
		v.RemoveBlockedHost("dynamic.example.com")
		assert.False(t, v.isBlockedHost("dynamic.example.com"))
	})
}

func TestURLValidator_DynamicCIDRManagement(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("add allowed CIDR", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              true,
			BlockLoopback:                true,
			BlockLinkLocal:               true,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Initially blocked
		err = v.ValidateURL("http://10.1.0.1:8080")
		assert.Error(t, err)

		// Add CIDR to allowed
		err = v.AddAllowedCIDR("10.1.0.0/24")
		require.NoError(t, err)

		// Now allowed
		err = v.ValidateURL("http://10.1.0.1:8080")
		assert.NoError(t, err)
	})

	t.Run("add blocked CIDR", func(t *testing.T) {
		config := &URLValidatorConfig{
			BlockPrivateIPs:              false,
			BlockLoopback:                false,
			BlockLinkLocal:               false,
			AllowedSchemes:               []string{"http", "https"},
			EnableDNSRebindingProtection: false,
		}
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		// Initially allowed
		err = v.ValidateURL("http://203.0.113.1:8080")
		assert.NoError(t, err)

		// Add CIDR to blocked
		err = v.AddBlockedCIDR("203.0.113.0/24")
		require.NoError(t, err)

		// Now blocked
		err = v.ValidateURL("http://203.0.113.1:8080")
		assert.Error(t, err)
	})

	t.Run("add invalid CIDR returns error", func(t *testing.T) {
		v, err := NewURLValidator(DefaultURLValidatorConfig(), logger)
		require.NoError(t, err)

		err = v.AddAllowedCIDR("invalid")
		assert.Error(t, err)

		err = v.AddBlockedCIDR("invalid")
		assert.Error(t, err)
	})
}

func TestURLValidator_GetConfig(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("returns config", func(t *testing.T) {
		config := DefaultURLValidatorConfig()
		v, err := NewURLValidator(config, logger)
		require.NoError(t, err)

		returnedConfig := v.GetConfig()
		assert.Equal(t, config, returnedConfig)
	})
}

func TestDefaultURLValidatorConfig(t *testing.T) {
	config := DefaultURLValidatorConfig()

	assert.True(t, config.BlockPrivateIPs)
	assert.True(t, config.BlockLoopback)
	assert.True(t, config.BlockLinkLocal)
	assert.True(t, config.EnableDNSRebindingProtection)
	assert.Equal(t, []string{"http", "https"}, config.AllowedSchemes)
	assert.Equal(t, 2*time.Second, config.DNSResolutionTimeout)
}

// Benchmark tests
func BenchmarkURLValidator_ValidateURL_PublicIP(b *testing.B) {
	logger := zap.NewNop()
	config := &URLValidatorConfig{
		BlockPrivateIPs:              true,
		BlockLoopback:                true,
		BlockLinkLocal:               true,
		AllowedSchemes:               []string{"http", "https"},
		EnableDNSRebindingProtection: false,
	}
	v, _ := NewURLValidator(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.ValidateURL("http://8.8.8.8:80")
	}
}

func BenchmarkURLValidator_ValidateURL_PrivateIP(b *testing.B) {
	logger := zap.NewNop()
	config := &URLValidatorConfig{
		BlockPrivateIPs:              true,
		BlockLoopback:                true,
		BlockLinkLocal:               true,
		AllowedSchemes:               []string{"http", "https"},
		EnableDNSRebindingProtection: false,
	}
	v, _ := NewURLValidator(config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.ValidateURL("http://192.168.1.1:80")
	}
}
