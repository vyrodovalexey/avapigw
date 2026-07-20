package proxy

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestConnectionPool_Get_DualStackHostnameFallsBackToIPv4 is the regression
// test for the dual-stack dial preference: "localhost" resolves to both
// ::1 and 127.0.0.1 on dual-stack machines, but the server below listens on
// IPv4 only. With the passthrough-normalized target the unresolved hostname
// reaches net.Dialer, whose RFC 6555 Happy Eyeballs handling connects over
// the reachable IPv4 address instead of pinning to an unusable family.
func TestConnectionPool_Get_DualStackHostnameFallsBackToIPv4(t *testing.T) {
	t.Parallel()

	// IPv4-only listener with no registered services: a successful
	// TCP+HTTP/2 handshake yields codes.Unimplemented on Invoke, while a
	// broken dial yields codes.Unavailable.
	lis, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	go func() { _ = server.Serve(lis) }()
	defer server.Stop()

	port := lis.Addr().(*net.TCPAddr).Port
	target := net.JoinHostPort("localhost", strconv.Itoa(port))

	pool := NewConnectionPool()
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pool.Get(ctx, target)
	require.NoError(t, err)
	require.NotNil(t, conn)

	var reply []byte
	invokeErr := conn.Invoke(ctx, "/test.Service/Ping", []byte{}, &reply)
	require.Error(t, invokeErr)
	assert.Equal(t, codes.Unimplemented, status.Code(invokeErr),
		"hostname dial must reach the IPv4-only server (got %v)", invokeErr)
}

// TestConnectionPool_Get_PoolKeyStaysRawTarget verifies the passthrough
// normalization is applied only at dial time: pool bookkeeping (map keys,
// Targets, CloseConn) keeps using the caller's raw host:port target.
func TestConnectionPool_Get_PoolKeyStaysRawTarget(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const target = "localhost:65100"
	conn, err := pool.Get(ctx, target)
	require.NoError(t, err)
	require.NotNil(t, conn)

	assert.Equal(t, []string{target}, pool.Targets())
	require.NoError(t, pool.CloseConn(target))
	assert.Zero(t, pool.Size())
}
