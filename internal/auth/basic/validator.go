// Package basic provides basic authentication validation for the API Gateway.
package basic

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// Common errors for basic authentication.
var (
	ErrMissingCredentials = errors.New("missing credentials")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidHeader      = errors.New("invalid authorization header")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserDisabled       = errors.New("user is disabled")
)

// Default realm for basic authentication.
const defaultRealm = "Restricted"

// Metrics for basic auth validation.
var (
	basicAuthValidationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_basic_auth_validation_total",
			Help: "Total number of basic auth validation attempts",
		},
		[]string{"result"},
	)

	basicAuthValidationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "avapigw_basic_auth_validation_duration_seconds",
			Help:    "Duration of basic auth validation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"result"},
	)
)

// User represents a user for basic authentication.
type User struct {
	// Username is the user's username.
	Username string `json:"username"`

	// PasswordHash is the bcrypt hash of the user's password.
	PasswordHash string `json:"passwordHash"`

	// Roles is the list of roles assigned to the user.
	Roles []string `json:"roles,omitempty"`

	// Groups is the list of groups the user belongs to.
	Groups []string `json:"groups,omitempty"`

	// Metadata is additional metadata for the user.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Enabled indicates whether the user is enabled.
	Enabled bool `json:"enabled"`

	// CreatedAt is when the user was created.
	CreatedAt time.Time `json:"createdAt"`

	// LastLoginAt is when the user last logged in.
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
}

// HasRole checks if the user has the specified role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasGroup checks if the user belongs to the specified group.
func (u *User) HasGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// Store defines the interface for user storage.
type Store interface {
	// Get retrieves a user by username.
	Get(ctx context.Context, username string) (*User, error)

	// List returns all users.
	List(ctx context.Context) ([]*User, error)

	// Create creates a new user.
	Create(ctx context.Context, user *User) error

	// Update updates an existing user.
	Update(ctx context.Context, user *User) error

	// Delete deletes a user by username.
	Delete(ctx context.Context, username string) error
}

// MemoryStore is an in-memory implementation of the Store interface.
type MemoryStore struct {
	users map[string]*User
	mu    sync.RWMutex
}

// NewMemoryStore creates a new in-memory user store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: make(map[string]*User),
	}
}

// Get retrieves a user by username.
func (s *MemoryStore) Get(ctx context.Context, username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// List returns all users.
func (s *MemoryStore) List(ctx context.Context) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	return users, nil
}

// Create creates a new user.
func (s *MemoryStore) Create(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.Username]; exists {
		return errors.New("user already exists")
	}

	s.users[user.Username] = user
	return nil
}

// Update updates an existing user.
func (s *MemoryStore) Update(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.Username]; !exists {
		return ErrUserNotFound
	}

	s.users[user.Username] = user
	return nil
}

// Delete deletes a user by username.
func (s *MemoryStore) Delete(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; !exists {
		return ErrUserNotFound
	}

	delete(s.users, username)
	return nil
}

// AddUser adds a user with a plaintext password (will be hashed).
func (s *MemoryStore) AddUser(username, password string, roles, groups []string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	user := &User{
		Username:     username,
		PasswordHash: hash,
		Roles:        roles,
		Groups:       groups,
		Enabled:      true,
		CreatedAt:    time.Now(),
	}

	return s.Create(context.Background(), user)
}

// LoadFromSecretData loads users from Kubernetes secret data.
// The secret data is expected to be a map of usernames to passwords.
func (s *MemoryStore) LoadFromSecretData(data map[string][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for username, password := range data {
		hash, err := HashPassword(string(password))
		if err != nil {
			return err
		}

		s.users[username] = &User{
			Username:     username,
			PasswordHash: hash,
			Enabled:      true,
			CreatedAt:    time.Now(),
		}
	}

	return nil
}

// LoadFromHashedSecretData loads users from Kubernetes secret data with pre-hashed passwords.
// The secret data is expected to be a map of usernames to bcrypt hashes.
func (s *MemoryStore) LoadFromHashedSecretData(data map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for username, hash := range data {
		s.users[username] = &User{
			Username:     username,
			PasswordHash: string(hash),
			Enabled:      true,
			CreatedAt:    time.Now(),
		}
	}
}

// Validator validates basic authentication credentials.
type Validator struct {
	store  Store
	realm  string
	logger *zap.Logger
}

// ValidatorConfig holds configuration for the basic auth validator.
type ValidatorConfig struct {
	Store  Store
	Realm  string
	Logger *zap.Logger
}

// NewValidator creates a new basic auth validator.
func NewValidator(store Store, realm string, logger *zap.Logger) *Validator {
	if logger == nil {
		logger = zap.NewNop()
	}
	if realm == "" {
		realm = defaultRealm
	}

	return &Validator{
		store:  store,
		realm:  realm,
		logger: logger,
	}
}

// NewValidatorWithConfig creates a new basic auth validator with custom configuration.
func NewValidatorWithConfig(config *ValidatorConfig) *Validator {
	if config.Logger == nil {
		config.Logger = zap.NewNop()
	}
	if config.Realm == "" {
		config.Realm = defaultRealm
	}

	return &Validator{
		store:  config.Store,
		realm:  config.Realm,
		logger: config.Logger,
	}
}

// Validate validates basic auth credentials and returns the user.
func (v *Validator) Validate(ctx context.Context, username, password string) (*User, error) {
	start := time.Now()
	result := "success"

	defer func() {
		duration := time.Since(start).Seconds()
		basicAuthValidationTotal.WithLabelValues(result).Inc()
		basicAuthValidationDuration.WithLabelValues(result).Observe(duration)
	}()

	if username == "" || password == "" {
		result = "missing_credentials"
		return nil, ErrMissingCredentials
	}

	// Get the user
	user, err := v.store.Get(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			result = "user_not_found"
			// Use constant-time comparison to prevent timing attacks
			// nolint:gosec // G101 false positive: dummy hash for timing attack prevention, not a real secret
			_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy"), []byte(password)) // NOSONAR
			return nil, ErrInvalidCredentials
		}
		result = "store_error"
		v.logger.Error("failed to get user from store",
			zap.String("username", username),
			zap.Error(err),
		)
		return nil, err
	}

	// Check if the user is enabled
	if !user.Enabled {
		result = "user_disabled"
		return nil, ErrUserDisabled
	}

	// Verify the password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		result = "invalid_password"
		return nil, ErrInvalidCredentials
	}

	v.logger.Debug("basic auth validated successfully",
		zap.String("username", username),
	)

	return user, nil
}

// ValidateRequest validates basic auth credentials from an HTTP request.
func (v *Validator) ValidateRequest(ctx context.Context, r *http.Request) (*User, error) {
	username, password, err := ExtractCredentials(r)
	if err != nil {
		return nil, err
	}

	return v.Validate(ctx, username, password)
}

// Realm returns the authentication realm.
func (v *Validator) Realm() string {
	return v.realm
}

// ExtractCredentials extracts basic auth credentials from an HTTP request.
func ExtractCredentials(r *http.Request) (username, password string, err error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", ErrMissingCredentials
	}

	// Check for "Basic " prefix
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", ErrInvalidHeader
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", ErrInvalidHeader
	}

	// Split username:password
	credentials := string(decoded)
	idx := strings.IndexByte(credentials, ':')
	if idx < 0 {
		return "", "", ErrInvalidHeader
	}

	return credentials[:idx], credentials[idx+1:], nil
}

// HashPassword hashes a password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePassword compares a password with a bcrypt hash.
func ComparePassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ComparePasswordConstantTime compares a password with a bcrypt hash using constant-time comparison.
func ComparePasswordConstantTime(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// EncodeCredentials encodes username and password for basic auth.
func EncodeCredentials(username, password string) string {
	credentials := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// SimpleValidator validates against a static map of username:password pairs.
type SimpleValidator struct {
	credentials map[string]string // username -> password hash
	realm       string
}

// NewSimpleValidator creates a new simple validator.
func NewSimpleValidator(credentials map[string]string, realm string) *SimpleValidator {
	if realm == "" {
		realm = defaultRealm
	}

	// Hash all passwords
	hashedCredentials := make(map[string]string)
	for username, password := range credentials {
		hash, err := HashPassword(password)
		if err != nil {
			continue
		}
		hashedCredentials[username] = hash
	}

	return &SimpleValidator{
		credentials: hashedCredentials,
		realm:       realm,
	}
}

// NewSimpleValidatorWithHashes creates a new simple validator with pre-hashed passwords.
func NewSimpleValidatorWithHashes(credentials map[string]string, realm string) *SimpleValidator {
	if realm == "" {
		realm = defaultRealm
	}

	return &SimpleValidator{
		credentials: credentials,
		realm:       realm,
	}
}

// Validate validates basic auth credentials.
func (v *SimpleValidator) Validate(ctx context.Context, username, password string) (*User, error) {
	hash, ok := v.credentials[username]
	if !ok {
		// Use constant-time comparison to prevent timing attacks
		// nolint:gosec // G101 false positive: dummy hash for timing attack prevention, not a real secret
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$dummy"), []byte(password)) // NOSONAR
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &User{
		Username: username,
		Enabled:  true,
	}, nil
}

// ValidateRequest validates basic auth credentials from an HTTP request.
func (v *SimpleValidator) ValidateRequest(ctx context.Context, r *http.Request) (*User, error) {
	username, password, err := ExtractCredentials(r)
	if err != nil {
		return nil, err
	}

	return v.Validate(ctx, username, password)
}

// Realm returns the authentication realm.
func (v *SimpleValidator) Realm() string {
	return v.realm
}

// PlaintextValidator validates against plaintext passwords (for testing only).
type PlaintextValidator struct {
	credentials map[string]string // username -> plaintext password
	realm       string
}

// NewPlaintextValidator creates a new plaintext validator (for testing only).
func NewPlaintextValidator(credentials map[string]string, realm string) *PlaintextValidator {
	if realm == "" {
		realm = defaultRealm
	}

	return &PlaintextValidator{
		credentials: credentials,
		realm:       realm,
	}
}

// Validate validates basic auth credentials using plaintext comparison.
func (v *PlaintextValidator) Validate(ctx context.Context, username, password string) (*User, error) {
	expectedPassword, ok := v.credentials[username]
	if !ok {
		return nil, ErrInvalidCredentials
	}

	// Use constant-time comparison
	if subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) != 1 {
		return nil, ErrInvalidCredentials
	}

	return &User{
		Username: username,
		Enabled:  true,
	}, nil
}

// ValidateRequest validates basic auth credentials from an HTTP request.
func (v *PlaintextValidator) ValidateRequest(ctx context.Context, r *http.Request) (*User, error) {
	username, password, err := ExtractCredentials(r)
	if err != nil {
		return nil, err
	}

	return v.Validate(ctx, username, password)
}

// Realm returns the authentication realm.
func (v *PlaintextValidator) Realm() string {
	return v.realm
}

// UserContextKey is the context key for storing user information.
type UserContextKey struct{}

// GetUserFromContext retrieves the user from the context.
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey{}).(*User)
	return user, ok
}

// ContextWithUser returns a new context with the user.
func ContextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, UserContextKey{}, user)
}
