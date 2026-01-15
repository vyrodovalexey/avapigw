// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewConnectionTracker(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name            string
		maxConns        int
		expectedMaxConn int
	}{
		{
			name:            "with positive max connections",
			maxConns:        100,
			expectedMaxConn: 100,
		},
		{
			name:            "with zero max connections uses default",
			maxConns:        0,
			expectedMaxConn: 10000,
		},
		{
			name:            "with negative max connections uses default",
			maxConns:        -1,
			expectedMaxConn: 10000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewConnectionTracker(tt.maxConns, logger)

			assert.NotNil(t, tracker)
			assert.Equal(t, tt.expectedMaxConn, tracker.maxConns)
			assert.Equal(t, 0, tracker.Count())
		})
	}
}

func TestConnectionTracker_Add(t *testing.T) {
	logger := zap.NewNop()

	t.Run("adds connection successfully", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked, err := tracker.Add(client)

		require.NoError(t, err)
		assert.NotNil(t, tracked)
		assert.NotEmpty(t, tracked.ID)
		assert.Equal(t, client.RemoteAddr().String(), tracked.RemoteAddr)
		assert.Equal(t, client.LocalAddr().String(), tracked.LocalAddr)
		assert.Equal(t, 1, tracker.Count())
	})

	t.Run("returns error when max connections reached", func(t *testing.T) {
		tracker := NewConnectionTracker(2, logger)

		// Add connections up to max
		var conns []net.Conn
		for i := 0; i < 2; i++ {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			conns = append(conns, client)

			_, err := tracker.Add(client)
			require.NoError(t, err)
		}

		// Try to add one more
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked, err := tracker.Add(client)

		assert.Error(t, err)
		assert.Nil(t, tracked)
		assert.Contains(t, err.Error(), "maximum connections reached")
		assert.Equal(t, 2, tracker.Count())
	})

	t.Run("concurrent adds are safe", func(t *testing.T) {
		tracker := NewConnectionTracker(100, logger)
		var wg sync.WaitGroup
		numGoroutines := 50

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				server, client := net.Pipe()
				defer server.Close()
				defer client.Close()

				_, _ = tracker.Add(client)
			}()
		}

		wg.Wait()
		assert.LessOrEqual(t, tracker.Count(), numGoroutines)
	})
}

func TestConnectionTracker_Remove(t *testing.T) {
	logger := zap.NewNop()

	t.Run("removes existing connection", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked, err := tracker.Add(client)
		require.NoError(t, err)
		assert.Equal(t, 1, tracker.Count())

		tracker.Remove(tracked.ID)

		assert.Equal(t, 0, tracker.Count())
		assert.Nil(t, tracker.Get(tracked.ID))
	})

	t.Run("removing non-existent connection is safe", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)

		// Should not panic
		tracker.Remove("non-existent-id")

		assert.Equal(t, 0, tracker.Count())
	})

	t.Run("concurrent removes are safe", func(t *testing.T) {
		tracker := NewConnectionTracker(100, logger)
		var ids []string

		// Add connections
		for i := 0; i < 50; i++ {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			tracked, err := tracker.Add(client)
			require.NoError(t, err)
			ids = append(ids, tracked.ID)
		}

		// Remove concurrently
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				tracker.Remove(id)
			}(id)
		}

		wg.Wait()
		assert.Equal(t, 0, tracker.Count())
	})
}

func TestConnectionTracker_Get(t *testing.T) {
	logger := zap.NewNop()

	t.Run("gets existing connection", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked, err := tracker.Add(client)
		require.NoError(t, err)

		result := tracker.Get(tracked.ID)

		assert.NotNil(t, result)
		assert.Equal(t, tracked.ID, result.ID)
		assert.Equal(t, tracked.RemoteAddr, result.RemoteAddr)
	})

	t.Run("returns nil for non-existent connection", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)

		result := tracker.Get("non-existent-id")

		assert.Nil(t, result)
	})
}

func TestConnectionTracker_Count(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns correct count", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)

		assert.Equal(t, 0, tracker.Count())

		var conns []net.Conn
		for i := 0; i < 5; i++ {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			conns = append(conns, client)

			_, err := tracker.Add(client)
			require.NoError(t, err)
			assert.Equal(t, i+1, tracker.Count())
		}
	})
}

func TestConnectionTracker_List(t *testing.T) {
	logger := zap.NewNop()

	t.Run("returns all connections", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)
		var expectedIDs []string

		for i := 0; i < 3; i++ {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()

			tracked, err := tracker.Add(client)
			require.NoError(t, err)
			expectedIDs = append(expectedIDs, tracked.ID)
		}

		list := tracker.List()

		assert.Len(t, list, 3)
		for _, tracked := range list {
			assert.Contains(t, expectedIDs, tracked.ID)
		}
	})

	t.Run("returns empty list when no connections", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)

		list := tracker.List()

		assert.Empty(t, list)
	})
}

func TestConnectionTracker_CloseAll(t *testing.T) {
	logger := zap.NewNop()

	t.Run("closes all connections", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)
		var servers []net.Conn

		for i := 0; i < 3; i++ {
			server, client := net.Pipe()
			servers = append(servers, server)
			defer server.Close()
			defer client.Close()

			_, err := tracker.Add(client)
			require.NoError(t, err)
		}

		tracker.CloseAll()

		// Verify connections are closed by trying to read
		for _, server := range servers {
			buf := make([]byte, 1)
			_, err := server.Read(buf)
			assert.Error(t, err) // Should get error because connection is closed
		}
	})

	t.Run("handles empty tracker", func(t *testing.T) {
		tracker := NewConnectionTracker(10, logger)

		// Should not panic
		tracker.CloseAll()
	})
}

func TestTrackedConnection_GetStats(t *testing.T) {
	t.Run("returns correct stats", func(t *testing.T) {
		startTime := time.Now()
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: startTime,
			BytesIn:   100,
			BytesOut:  200,
		}

		bytesIn, bytesOut, duration := tracked.GetStats()

		assert.Equal(t, int64(100), bytesIn)
		assert.Equal(t, int64(200), bytesOut)
		assert.GreaterOrEqual(t, duration, time.Duration(0))
	})

	t.Run("returns zero stats for new connection", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		bytesIn, bytesOut, duration := tracked.GetStats()

		assert.Equal(t, int64(0), bytesIn)
		assert.Equal(t, int64(0), bytesOut)
		assert.GreaterOrEqual(t, duration, time.Duration(0))
	})
}

func TestTrackedConnection_AddBytesIn(t *testing.T) {
	t.Run("adds bytes correctly", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		tracked.AddBytesIn(100)
		tracked.AddBytesIn(50)

		bytesIn, _, _ := tracked.GetStats()
		assert.Equal(t, int64(150), bytesIn)
	})

	t.Run("concurrent adds are safe", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tracked.AddBytesIn(1)
			}()
		}

		wg.Wait()
		bytesIn, _, _ := tracked.GetStats()
		assert.Equal(t, int64(100), bytesIn)
	})
}

func TestTrackedConnection_AddBytesOut(t *testing.T) {
	t.Run("adds bytes correctly", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		tracked.AddBytesOut(100)
		tracked.AddBytesOut(50)

		_, bytesOut, _ := tracked.GetStats()
		assert.Equal(t, int64(150), bytesOut)
	})

	t.Run("concurrent adds are safe", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tracked.AddBytesOut(1)
			}()
		}

		wg.Wait()
		_, bytesOut, _ := tracked.GetStats()
		assert.Equal(t, int64(100), bytesOut)
	})
}

func TestTrackedConnection_Close(t *testing.T) {
	t.Run("closes underlying connection", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()

		tracked := &TrackedConnection{
			ID:   "test-id",
			conn: client,
		}

		err := tracked.Close()

		assert.NoError(t, err)

		// Verify connection is closed
		buf := make([]byte, 1)
		_, err = server.Read(buf)
		assert.Error(t, err)
	})

	t.Run("returns nil when conn is nil", func(t *testing.T) {
		tracked := &TrackedConnection{
			ID:   "test-id",
			conn: nil,
		}

		err := tracked.Close()

		assert.NoError(t, err)
	})
}

func TestNewCountingConn(t *testing.T) {
	t.Run("creates counting connection", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}

		countingConn := NewCountingConn(client, tracked)

		assert.NotNil(t, countingConn)
		assert.Equal(t, client, countingConn.Conn)
		assert.Equal(t, tracked, countingConn.tracked)
	})
}

func TestCountingConn_Read(t *testing.T) {
	t.Run("counts bytes read", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}
		countingConn := NewCountingConn(client, tracked)

		// Write data from server side
		go func() {
			server.Write([]byte("hello"))
		}()

		buf := make([]byte, 10)
		n, err := countingConn.Read(buf)

		assert.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "hello", string(buf[:n]))

		bytesIn, _, _ := tracked.GetStats()
		assert.Equal(t, int64(5), bytesIn)
	})

	t.Run("handles nil tracked connection", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		countingConn := NewCountingConn(client, nil)

		// Write data from server side
		go func() {
			server.Write([]byte("hello"))
		}()

		buf := make([]byte, 10)
		n, err := countingConn.Read(buf)

		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	})
}

func TestCountingConn_Write(t *testing.T) {
	t.Run("counts bytes written", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		tracked := &TrackedConnection{
			ID:        "test-id",
			StartTime: time.Now(),
		}
		countingConn := NewCountingConn(client, tracked)

		// Read from server side in goroutine
		go func() {
			buf := make([]byte, 10)
			server.Read(buf)
		}()

		n, err := countingConn.Write([]byte("hello"))

		assert.NoError(t, err)
		assert.Equal(t, 5, n)

		_, bytesOut, _ := tracked.GetStats()
		assert.Equal(t, int64(5), bytesOut)
	})

	t.Run("handles nil tracked connection", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		countingConn := NewCountingConn(client, nil)

		// Read from server side in goroutine
		go func() {
			buf := make([]byte, 10)
			server.Read(buf)
		}()

		n, err := countingConn.Write([]byte("hello"))

		assert.NoError(t, err)
		assert.Equal(t, 5, n)
	})
}
