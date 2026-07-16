package tls

import (
	"crypto/tls"
	"time"
)

// HandshakeErrorReasonVerifyFailed is the bounded reason label recorded when a
// TLS handshake fails during connection verification (VerifyConnection).
const HandshakeErrorReasonVerifyFailed = "verify_connection_failed"

// HandshakeObserver receives the measured duration and the negotiated
// connection state of a successfully completed TLS handshake.
type HandshakeObserver func(duration time.Duration, state *tls.ConnectionState)

// HandshakeErrorObserver receives a bounded reason label when a TLS handshake
// fails during connection verification.
type HandshakeErrorObserver func(reason string)

// InstrumentHandshakeTiming installs per-handshake duration measurement on cfg.
//
// Measurement window: the GetConfigForClient callback fires when the server
// receives the ClientHello (handshake start); the VerifyConnection callback of
// the per-connection config returned from it fires after certificate
// verification, immediately before the handshake completes (handshake end).
// The observed duration therefore covers the real server-side handshake,
// including any chained verification work.
//
// Correlation between the two callbacks is lexical: for every handshake the
// installed hook returns a per-connection clone of the effective config whose
// VerifyConnection closure captures the start timestamp. No shared state (such
// as a map keyed by connection) is required, so handshakes that abort midway
// cannot leak tracking entries — each closure is released together with its
// connection by the garbage collector.
//
// Existing callbacks are preserved: a previously installed GetConfigForClient
// is chained (its returned override, if any, becomes the effective config for
// the handshake) and the effective config's VerifyConnection chain runs before
// the observation.
//
// onSuccess is invoked exactly once per successfully verified handshake.
// onFailure (optional, may be nil) is invoked with a bounded reason when the
// chained VerifyConnection rejects the connection. Handshakes that abort
// before connection verification (for example a client certificate rejected
// under MUTUAL mode) are not observed here; those paths already record
// dedicated error metrics at their source.
//
// When cfg or onSuccess is nil the function is a no-op.
func InstrumentHandshakeTiming(cfg *tls.Config, onSuccess HandshakeObserver, onFailure HandshakeErrorObserver) {
	if cfg == nil || onSuccess == nil {
		return
	}

	origGetConfig := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		start := time.Now()

		effective := cfg
		if origGetConfig != nil {
			override, err := origGetConfig(hello)
			if err != nil {
				return nil, err
			}
			if override != nil {
				effective = override
			}
		}

		return perConnHandshakeConfig(effective, start, onSuccess, onFailure), nil
	}
}

// perConnHandshakeConfig clones the effective handshake config and wraps its
// VerifyConnection callback with the duration observation for one connection.
func perConnHandshakeConfig(
	effective *tls.Config,
	start time.Time,
	onSuccess HandshakeObserver,
	onFailure HandshakeErrorObserver,
) *tls.Config {
	perConn := effective.Clone()
	// The clone serves exactly one handshake; drop the hook so the
	// per-connection config cannot re-instrument itself if it is ever reused.
	perConn.GetConfigForClient = nil

	origVerify := perConn.VerifyConnection
	perConn.VerifyConnection = func(cs tls.ConnectionState) error {
		if origVerify != nil {
			if err := origVerify(cs); err != nil {
				if onFailure != nil {
					onFailure(HandshakeErrorReasonVerifyFailed)
				}
				return err
			}
		}
		onSuccess(time.Since(start), &cs)
		return nil
	}
	return perConn
}

// ConnectionStateMode derives the effective TLS mode of a completed handshake
// from its connection state: MUTUAL when the peer presented a certificate,
// SIMPLE otherwise.
func ConnectionStateMode(cs *tls.ConnectionState) TLSMode {
	if cs != nil && len(cs.PeerCertificates) > 0 {
		return TLSModeMutual
	}
	return TLSModeSimple
}

// NewHandshakeRecorder builds the handshake observers used to wire the
// handshake-duration histogram for a listener.
//
// Successful handshakes are recorded through the TLS manager when one is
// available (the manager labels the sample with its configured mode);
// otherwise they are recorded directly on the metrics recorder with the mode
// derived from the connection state. Failed connection verifications are
// recorded on the metrics recorder as bounded handshake errors.
//
// Either return value may be nil when the corresponding sink is unavailable;
// InstrumentHandshakeTiming handles nil observers safely.
func NewHandshakeRecorder(manager *Manager, metrics MetricsRecorder) (HandshakeObserver, HandshakeErrorObserver) {
	var onSuccess HandshakeObserver
	switch {
	case manager != nil:
		onSuccess = manager.RecordHandshake
	case metrics != nil:
		onSuccess = func(duration time.Duration, cs *tls.ConnectionState) {
			metrics.RecordHandshakeDuration(duration, cs.Version, ConnectionStateMode(cs))
		}
	}

	var onFailure HandshakeErrorObserver
	if metrics != nil {
		onFailure = metrics.RecordHandshakeError
	}
	return onSuccess, onFailure
}
