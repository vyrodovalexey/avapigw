package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// caPEMTestCert is a syntactically valid PEM block (single base64 line) so
// pem.Decode succeeds; content is not a real certificate (not needed for
// GetCAPEM, which returns the raw PEM).
const caPEMTestCert = "-----BEGIN CERTIFICATE-----\nZHVtbXk=\n-----END CERTIFICATE-----"

// newCAPEMTestClient builds a vault client against a mock server that
// serves the given JSON body on /v1/pki/cert/ca.
func newCAPEMTestClient(t *testing.T, body string, cacheEnabled bool) (Client, *httptest.Server, *int) {
	t.Helper()

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki/cert/ca" && r.Method == http.MethodGet {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	cfg := &Config{
		Enabled:    true,
		Address:    server.URL,
		AuthMethod: AuthMethodToken,
		Token:      "test-token",
	}
	if cacheEnabled {
		cfg.Cache = &CacheConfig{Enabled: true, TTL: time.Minute}
	}

	client, err := New(cfg, observability.NopLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client, server, &calls
}

func TestPKIClient_GetCAPEM_Success(t *testing.T) {
	body := `{"data": {"certificate": "` + strings.ReplaceAll(caPEMTestCert, "\n", `\n`) + `"}}`
	client, _, _ := newCAPEMTestClient(t, body, false)

	pemBytes, err := client.PKI().GetCAPEM(context.Background(), "pki")
	if err != nil {
		t.Fatalf("GetCAPEM() error = %v", err)
	}
	if string(pemBytes) != caPEMTestCert {
		t.Errorf("GetCAPEM() = %q, want %q", pemBytes, caPEMTestCert)
	}
}

func TestPKIClient_GetCAPEM_EmptyMount(t *testing.T) {
	client, _, _ := newCAPEMTestClient(t, `{}`, false)

	if _, err := client.PKI().GetCAPEM(context.Background(), ""); err == nil {
		t.Error("GetCAPEM() should return error for empty mount")
	}
}

func TestPKIClient_GetCAPEM_NoCertificateInResponse(t *testing.T) {
	client, _, _ := newCAPEMTestClient(t, `{"data": {"other": "value"}}`, false)

	if _, err := client.PKI().GetCAPEM(context.Background(), "pki"); err == nil {
		t.Error("GetCAPEM() should return error when certificate is missing")
	}
}

func TestPKIClient_GetCAPEM_NoData(t *testing.T) {
	client, _, _ := newCAPEMTestClient(t, `{}`, false)

	if _, err := client.PKI().GetCAPEM(context.Background(), "pki"); err == nil {
		t.Error("GetCAPEM() should return error for empty data")
	}
}

func TestPKIClient_GetCAPEM_InvalidPEM(t *testing.T) {
	client, _, _ := newCAPEMTestClient(t, `{"data": {"certificate": "not-a-pem"}}`, false)

	if _, err := client.PKI().GetCAPEM(context.Background(), "pki"); err == nil {
		t.Error("GetCAPEM() should return error for unparsable PEM")
	}
}

func TestPKIClient_GetCAPEM_RequestError(t *testing.T) {
	client, server, _ := newCAPEMTestClient(t, `{}`, false)
	server.Close() // force a transport error

	if _, err := client.PKI().GetCAPEM(context.Background(), "pki"); err == nil {
		t.Error("GetCAPEM() should return error when the server is unreachable")
	}
}

func TestPKIClient_GetCAPEM_Cached(t *testing.T) {
	body := `{"data": {"certificate": "` + strings.ReplaceAll(caPEMTestCert, "\n", `\n`) + `"}}`
	client, _, calls := newCAPEMTestClient(t, body, true)

	ctx := context.Background()
	if _, err := client.PKI().GetCAPEM(ctx, "pki"); err != nil {
		t.Fatalf("first GetCAPEM() error = %v", err)
	}
	if _, err := client.PKI().GetCAPEM(ctx, "pki"); err != nil {
		t.Fatalf("second GetCAPEM() error = %v", err)
	}

	if *calls != 1 {
		t.Errorf("GetCAPEM() server calls = %d, want 1 (second call must hit the cache)", *calls)
	}
}

func TestDisabledPKIClient_GetCAPEM(t *testing.T) {
	c := &disabledPKIClient{}
	if _, err := c.GetCAPEM(context.Background(), "pki"); err == nil {
		t.Error("disabled client GetCAPEM() should return ErrVaultDisabled")
	}
}
