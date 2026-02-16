package config

import "time"

// Duration is a wrapper around time.Duration that supports YAML/JSON marshaling.
// It enables human-readable duration strings (e.g., "30s", "5m", "1h30m") in
// configuration files while preserving type safety in Go code.
//
// Supported formats follow Go's time.ParseDuration syntax:
//   - "300ms"  → 300 milliseconds
//   - "30s"    → 30 seconds
//   - "5m"     → 5 minutes
//   - "1h30m"  → 1 hour and 30 minutes
//
// An empty string or JSON null unmarshals to zero duration.
//
// Example YAML usage:
//
//	timeout: "30s"
//	interval: "5m"
//
// Example Go usage:
//
//	d := config.Duration(5 * time.Second)
//	fmt.Println(d.Duration()) // 5s
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	// Remove quotes if present
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	duration, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(duration)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// Duration returns the time.Duration value.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}
