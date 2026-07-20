package util

import "testing"

func TestGRPCDialTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "bare hostname and port gets passthrough scheme",
			target: "host.docker.internal:8813",
			want:   "passthrough:///host.docker.internal:8813",
		},
		{
			name:   "bare IPv4 literal gets passthrough scheme",
			target: "192.168.65.254:8813",
			want:   "passthrough:///192.168.65.254:8813",
		},
		{
			name:   "bracketed IPv6 literal gets passthrough scheme",
			target: "[fdc4:f303:9324::254]:8813",
			want:   "passthrough:///[fdc4:f303:9324::254]:8813",
		},
		{
			name:   "localhost gets passthrough scheme",
			target: "localhost:9000",
			want:   "passthrough:///localhost:9000",
		},
		{
			name:   "explicit dns scheme unchanged",
			target: "dns:///svc.ns.svc.cluster.local:9000",
			want:   "dns:///svc.ns.svc.cluster.local:9000",
		},
		{
			name:   "explicit passthrough scheme unchanged",
			target: "passthrough:///backend:50051",
			want:   "passthrough:///backend:50051",
		},
		{
			name:   "unix socket unchanged",
			target: "unix:///var/run/backend.sock",
			want:   "unix:///var/run/backend.sock",
		},
		{
			name:   "relative unix socket unchanged",
			target: "unix:relative.sock",
			want:   "unix:relative.sock",
		},
		{
			name:   "unix-abstract unchanged",
			target: "unix-abstract:abstract-name",
			want:   "unix-abstract:abstract-name",
		},
		{
			name:   "ipv4 resolver scheme unchanged",
			target: "ipv4:10.0.0.1:50051",
			want:   "ipv4:10.0.0.1:50051",
		},
		{
			name:   "ipv6 resolver scheme unchanged",
			target: "ipv6:[::1]:50051",
			want:   "ipv6:[::1]:50051",
		},
		{
			name:   "xds scheme unchanged",
			target: "xds:///listener",
			want:   "xds:///listener",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GRPCDialTarget(tt.target); got != tt.want {
				t.Errorf("GRPCDialTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}
