package util

import "strings"

// grpcTargetSchemes are the gRPC name-resolution scheme prefixes that must
// be passed through unchanged by GRPCDialTarget. Bare "host:port" targets
// never start with one of these (a hostname cannot contain "//" and none of
// the schemes are valid hostnames followed by a port).
var grpcTargetSchemes = []string{
	"dns:",
	"unix:",
	"unix-abstract:",
	"passthrough:",
	"ipv4:",
	"ipv6:",
	"xds:",
}

// GRPCDialTarget normalizes a bare "host:port" gRPC dial target to an
// explicit "passthrough:///host:port" target.
//
// grpc.NewClient defaults to the "dns" resolver, which resolves the
// hostname itself and hands individual literal IP addresses to the
// transport dialer. That bypasses net.Dialer's RFC 6555 Happy Eyeballs
// fallback, so on dual-stack hostnames (A + AAAA records) a connection
// attempt can be pinned to an unreachable IPv6 address instead of falling
// back to IPv4. With the passthrough resolver the unresolved hostname
// reaches net.Dialer, which resolves it per dial attempt and applies the
// dual-stack IPv4 fallback natively.
//
// Targets that already carry an explicit gRPC resolver scheme are returned
// unchanged so callers can still opt into any resolver.
func GRPCDialTarget(target string) string {
	for _, scheme := range grpcTargetSchemes {
		if strings.HasPrefix(target, scheme) {
			return target
		}
	}
	return "passthrough:///" + target
}
