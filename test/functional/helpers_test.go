//go:build functional
// +build functional

package functional

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HTTPRequestBuilder helps build HTTP requests for testing
type HTTPRequestBuilder struct {
	method  string
	url     string
	headers map[string]string
	body    io.Reader
	timeout time.Duration
}

// NewHTTPRequest creates a new HTTP request builder
func NewHTTPRequest(method, url string) *HTTPRequestBuilder {
	return &HTTPRequestBuilder{
		method:  method,
		url:     url,
		headers: make(map[string]string),
		timeout: 10 * time.Second,
	}
}

// WithHeader adds a header to the request
func (b *HTTPRequestBuilder) WithHeader(key, value string) *HTTPRequestBuilder {
	b.headers[key] = value
	return b
}

// WithHeaders adds multiple headers to the request
func (b *HTTPRequestBuilder) WithHeaders(headers map[string]string) *HTTPRequestBuilder {
	for k, v := range headers {
		b.headers[k] = v
	}
	return b
}

// WithBody sets the request body
func (b *HTTPRequestBuilder) WithBody(body string) *HTTPRequestBuilder {
	b.body = strings.NewReader(body)
	return b
}

// WithJSONBody sets the request body as JSON
func (b *HTTPRequestBuilder) WithJSONBody(v interface{}) *HTTPRequestBuilder {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal JSON body: %v", err))
	}
	b.body = bytes.NewReader(data)
	b.headers["Content-Type"] = "application/json"
	return b
}

// WithTimeout sets the request timeout
func (b *HTTPRequestBuilder) WithTimeout(d time.Duration) *HTTPRequestBuilder {
	b.timeout = d
	return b
}

// Build builds the HTTP request
func (b *HTTPRequestBuilder) Build(t *testing.T) *http.Request {
	req, err := http.NewRequest(b.method, b.url, b.body)
	require.NoError(t, err)

	for k, v := range b.headers {
		req.Header.Set(k, v)
	}

	return req
}

// Do executes the HTTP request
func (b *HTTPRequestBuilder) Do(t *testing.T, client *http.Client) *http.Response {
	req := b.Build(t)

	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	require.NoError(t, err)

	return resp
}

// HTTPResponseAsserter helps assert HTTP responses
type HTTPResponseAsserter struct {
	t    *testing.T
	resp *http.Response
	body []byte
}

// NewHTTPResponseAsserter creates a new response asserter
func NewHTTPResponseAsserter(t *testing.T, resp *http.Response) *HTTPResponseAsserter {
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	resp.Body.Close()

	return &HTTPResponseAsserter{
		t:    t,
		resp: resp,
		body: body,
	}
}

// AssertStatus asserts the response status code
func (a *HTTPResponseAsserter) AssertStatus(expected int) *HTTPResponseAsserter {
	assert.Equal(a.t, expected, a.resp.StatusCode, "unexpected status code")
	return a
}

// AssertHeader asserts a response header value
func (a *HTTPResponseAsserter) AssertHeader(key, expected string) *HTTPResponseAsserter {
	assert.Equal(a.t, expected, a.resp.Header.Get(key), "unexpected header value for %s", key)
	return a
}

// AssertHeaderExists asserts a response header exists
func (a *HTTPResponseAsserter) AssertHeaderExists(key string) *HTTPResponseAsserter {
	assert.NotEmpty(a.t, a.resp.Header.Get(key), "header %s should exist", key)
	return a
}

// AssertHeaderNotExists asserts a response header does not exist
func (a *HTTPResponseAsserter) AssertHeaderNotExists(key string) *HTTPResponseAsserter {
	assert.Empty(a.t, a.resp.Header.Get(key), "header %s should not exist", key)
	return a
}

// AssertHeaderContains asserts a response header contains a value
func (a *HTTPResponseAsserter) AssertHeaderContains(key, substring string) *HTTPResponseAsserter {
	assert.Contains(a.t, a.resp.Header.Get(key), substring, "header %s should contain %s", key, substring)
	return a
}

// AssertBodyContains asserts the response body contains a string
func (a *HTTPResponseAsserter) AssertBodyContains(substring string) *HTTPResponseAsserter {
	assert.Contains(a.t, string(a.body), substring, "body should contain %s", substring)
	return a
}

// AssertBodyEquals asserts the response body equals a string
func (a *HTTPResponseAsserter) AssertBodyEquals(expected string) *HTTPResponseAsserter {
	assert.Equal(a.t, expected, string(a.body), "unexpected body")
	return a
}

// AssertJSONPath asserts a JSON path value
func (a *HTTPResponseAsserter) AssertJSONPath(path string, expected interface{}) *HTTPResponseAsserter {
	var data map[string]interface{}
	err := json.Unmarshal(a.body, &data)
	require.NoError(a.t, err)

	// Simple path parsing (supports single level)
	value, ok := data[path]
	assert.True(a.t, ok, "JSON path %s not found", path)
	assert.Equal(a.t, expected, value, "unexpected value at JSON path %s", path)
	return a
}

// Body returns the response body
func (a *HTTPResponseAsserter) Body() []byte {
	return a.body
}

// Response returns the HTTP response
func (a *HTTPResponseAsserter) Response() *http.Response {
	return a.resp
}

// ConcurrentRequester executes concurrent HTTP requests
type ConcurrentRequester struct {
	client      *http.Client
	concurrency int
	requests    int
	results     []RequestResult
}

// RequestResult holds the result of a single request
type RequestResult struct {
	StatusCode int
	Duration   time.Duration
	Error      error
	Body       []byte
}

// NewConcurrentRequester creates a new concurrent requester
func NewConcurrentRequester(client *http.Client, concurrency, requests int) *ConcurrentRequester {
	return &ConcurrentRequester{
		client:      client,
		concurrency: concurrency,
		requests:    requests,
		results:     make([]RequestResult, 0, requests),
	}
}

// Execute executes concurrent requests
func (cr *ConcurrentRequester) Execute(t *testing.T, method, url string) []RequestResult {
	results := make(chan RequestResult, cr.requests)
	semaphore := make(chan struct{}, cr.concurrency)
	var wg sync.WaitGroup

	for i := 0; i < cr.requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			start := time.Now()
			req, err := http.NewRequest(method, url, nil)
			if err != nil {
				results <- RequestResult{Error: err}
				return
			}

			resp, err := cr.client.Do(req)
			duration := time.Since(start)

			if err != nil {
				results <- RequestResult{Error: err, Duration: duration}
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			results <- RequestResult{
				StatusCode: resp.StatusCode,
				Duration:   duration,
				Body:       body,
			}
		}()
	}

	// Wait for all goroutines to complete and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results with proper synchronization
	collectedResults := make([]RequestResult, 0, cr.requests)
	for result := range results {
		collectedResults = append(collectedResults, result)
	}

	cr.results = collectedResults
	return cr.results
}

// CountByStatus counts results by status code
func (cr *ConcurrentRequester) CountByStatus(statusCode int) int {
	count := 0
	for _, r := range cr.results {
		if r.StatusCode == statusCode {
			count++
		}
	}
	return count
}

// CountErrors counts results with errors
func (cr *ConcurrentRequester) CountErrors() int {
	count := 0
	for _, r := range cr.results {
		if r.Error != nil {
			count++
		}
	}
	return count
}

// AverageDuration returns the average request duration
func (cr *ConcurrentRequester) AverageDuration() time.Duration {
	if len(cr.results) == 0 {
		return 0
	}

	var total time.Duration
	for _, r := range cr.results {
		total += r.Duration
	}
	return total / time.Duration(len(cr.results))
}

// MaxDuration returns the maximum request duration
func (cr *ConcurrentRequester) MaxDuration() time.Duration {
	var max time.Duration
	for _, r := range cr.results {
		if r.Duration > max {
			max = r.Duration
		}
	}
	return max
}

// MinDuration returns the minimum request duration
func (cr *ConcurrentRequester) MinDuration() time.Duration {
	if len(cr.results) == 0 {
		return 0
	}

	min := cr.results[0].Duration
	for _, r := range cr.results[1:] {
		if r.Duration < min {
			min = r.Duration
		}
	}
	return min
}

// RetryHelper helps with retry logic in tests
type RetryHelper struct {
	maxRetries int
	delay      time.Duration
	backoff    float64
}

// NewRetryHelper creates a new retry helper
func NewRetryHelper(maxRetries int, delay time.Duration) *RetryHelper {
	return &RetryHelper{
		maxRetries: maxRetries,
		delay:      delay,
		backoff:    1.5,
	}
}

// WithBackoff sets the backoff multiplier
func (r *RetryHelper) WithBackoff(backoff float64) *RetryHelper {
	r.backoff = backoff
	return r
}

// Do executes a function with retries
func (r *RetryHelper) Do(t *testing.T, fn func() error) error {
	var lastErr error
	delay := r.delay

	for i := 0; i <= r.maxRetries; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			lastErr = err
			if i < r.maxRetries {
				time.Sleep(delay)
				delay = time.Duration(float64(delay) * r.backoff)
			}
		}
	}

	return fmt.Errorf("failed after %d retries: %w", r.maxRetries, lastErr)
}

// DoUntilSuccess executes a function until it succeeds or timeout
func (r *RetryHelper) DoUntilSuccess(t *testing.T, timeout time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	delay := r.delay

	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return nil
		}
		time.Sleep(delay)
		delay = time.Duration(float64(delay) * r.backoff)
		if delay > timeout/2 {
			delay = timeout / 2
		}
	}

	return fmt.Errorf("timeout after %v", timeout)
}

// TestCase represents a test case for table-driven tests
type TestCase struct {
	Name           string
	Setup          func(t *testing.T)
	Teardown       func(t *testing.T)
	Request        func(t *testing.T) *http.Request
	ExpectedStatus int
	ExpectedBody   string
	Assertions     func(t *testing.T, resp *http.Response, body []byte)
}

// RunTestCases runs a slice of test cases
func RunTestCases(t *testing.T, client *http.Client, cases []TestCase) {
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Setup != nil {
				tc.Setup(t)
			}
			if tc.Teardown != nil {
				defer tc.Teardown(t)
			}

			req := tc.Request(t)
			resp, err := client.Do(req)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			resp.Body.Close()

			if tc.ExpectedStatus != 0 {
				assert.Equal(t, tc.ExpectedStatus, resp.StatusCode)
			}

			if tc.ExpectedBody != "" {
				assert.Equal(t, tc.ExpectedBody, string(body))
			}

			if tc.Assertions != nil {
				tc.Assertions(t, resp, body)
			}
		})
	}
}

// PortScanner helps find available ports
type PortScanner struct {
	startPort int
	endPort   int
}

// NewPortScanner creates a new port scanner
func NewPortScanner(startPort, endPort int) *PortScanner {
	return &PortScanner{
		startPort: startPort,
		endPort:   endPort,
	}
}

// FindAvailablePorts finds n available ports
func (ps *PortScanner) FindAvailablePorts(t *testing.T, n int) []int {
	ports := make([]int, 0, n)
	for port := ps.startPort; port <= ps.endPort && len(ports) < n; port++ {
		if ps.isPortAvailable(port) {
			ports = append(ports, port)
		}
	}
	require.Len(t, ports, n, "could not find %d available ports", n)
	return ports
}

func (ps *PortScanner) isPortAvailable(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// MetricsCollector collects metrics during tests
type MetricsCollector struct {
	requestCount    int
	successCount    int
	failureCount    int
	totalLatency    time.Duration
	latencies       []time.Duration
	statusCodeCount map[int]int
	mu              sync.Mutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		latencies:       make([]time.Duration, 0),
		statusCodeCount: make(map[int]int),
	}
}

// Record records a request result
func (mc *MetricsCollector) Record(statusCode int, latency time.Duration, success bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.requestCount++
	mc.totalLatency += latency
	mc.latencies = append(mc.latencies, latency)
	mc.statusCodeCount[statusCode]++

	if success {
		mc.successCount++
	} else {
		mc.failureCount++
	}
}

// RequestCount returns the total request count
func (mc *MetricsCollector) RequestCount() int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.requestCount
}

// SuccessRate returns the success rate
func (mc *MetricsCollector) SuccessRate() float64 {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.requestCount == 0 {
		return 0
	}
	return float64(mc.successCount) / float64(mc.requestCount)
}

// AverageLatency returns the average latency
func (mc *MetricsCollector) AverageLatency() time.Duration {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.requestCount == 0 {
		return 0
	}
	return mc.totalLatency / time.Duration(mc.requestCount)
}

// P99Latency returns the 99th percentile latency
func (mc *MetricsCollector) P99Latency() time.Duration {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if len(mc.latencies) == 0 {
		return 0
	}

	// Sort latencies using standard library sort.Slice
	sorted := make([]time.Duration, len(mc.latencies))
	copy(sorted, mc.latencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	idx := int(float64(len(sorted)) * 0.99)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// StatusCodeCount returns the count for a specific status code
func (mc *MetricsCollector) StatusCodeCount(statusCode int) int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.statusCodeCount[statusCode]
}

// Reset resets the metrics collector
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.requestCount = 0
	mc.successCount = 0
	mc.failureCount = 0
	mc.totalLatency = 0
	mc.latencies = make([]time.Duration, 0)
	mc.statusCodeCount = make(map[int]int)
}
