// Package audit provides audit logging capabilities for the API Gateway.
//
// This package implements comprehensive audit logging for security-relevant events:
//   - Authentication events (success, failure)
//   - Authorization events (allowed, denied)
//   - Configuration changes
//   - Administrative actions
//
// # Architecture
//
// The audit package provides:
//   - Event types for different audit scenarios
//   - Configurable audit logger with multiple outputs
//   - Structured audit log format
//
// # Usage
//
// Create an audit logger with the desired configuration:
//
//	cfg := &audit.Config{
//	    Enabled: true,
//	    Level:   audit.LevelInfo,
//	    Output:  "stdout",
//	    Format:  "json",
//	}
//
//	logger, err := audit.NewLogger(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Log an authentication event
//	logger.LogEvent(ctx, &audit.Event{
//	    Type:      audit.EventTypeAuthentication,
//	    Action:    audit.ActionLogin,
//	    Outcome:   audit.OutcomeSuccess,
//	    Subject:   "user@example.com",
//	    Resource:  "/api/v1/users",
//	})
package audit
