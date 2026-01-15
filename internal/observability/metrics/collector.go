// Package metrics provides Prometheus metrics for the API Gateway.
package metrics

import (
	"runtime"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// REDMetrics implements Rate, Errors, Duration metrics pattern.
type REDMetrics struct {
	requestsTotal   *prometheus.CounterVec
	errorsTotal     *prometheus.CounterVec
	durationSeconds *prometheus.HistogramVec
}

// NewREDMetrics creates a new REDMetrics instance.
func NewREDMetrics(namespace, subsystem, name string, labels []string) *REDMetrics {
	return &REDMetrics{
		requestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      name + "_requests_total",
				Help:      "Total number of " + name + " requests",
			},
			labels,
		),
		errorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      name + "_errors_total",
				Help:      "Total number of " + name + " errors",
			},
			labels,
		),
		durationSeconds: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      name + "_duration_seconds",
				Help:      name + " duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			labels,
		),
	}
}

// RecordRequest records a request with the given labels.
func (r *REDMetrics) RecordRequest(labels ...string) {
	r.requestsTotal.WithLabelValues(labels...).Inc()
}

// RecordError records an error with the given labels.
func (r *REDMetrics) RecordError(labels ...string) {
	r.errorsTotal.WithLabelValues(labels...).Inc()
}

// RecordDuration records a duration with the given labels.
func (r *REDMetrics) RecordDuration(duration float64, labels ...string) {
	r.durationSeconds.WithLabelValues(labels...).Observe(duration)
}

// Record records a complete request with rate, error (if applicable), and duration.
func (r *REDMetrics) Record(duration float64, isError bool, labels ...string) {
	r.requestsTotal.WithLabelValues(labels...).Inc()
	if isError {
		r.errorsTotal.WithLabelValues(labels...).Inc()
	}
	r.durationSeconds.WithLabelValues(labels...).Observe(duration)
}

// GatewayCollector collects gateway-specific metrics.
type GatewayCollector struct {
	mu sync.RWMutex

	// Gateway info
	gatewayInfo *prometheus.GaugeVec

	// Uptime
	startTime time.Time
	uptime    prometheus.Gauge

	// Runtime metrics
	goroutines prometheus.Gauge
	threads    prometheus.Gauge
	heapAlloc  prometheus.Gauge
	heapSys    prometheus.Gauge
	gcPause    prometheus.Histogram

	// Connection metrics
	activeConnections   prometheus.Gauge
	totalConnections    prometheus.Counter
	connectionErrors    prometheus.Counter
	connectionDurations prometheus.Histogram

	// Request metrics
	requestsInProgress prometheus.Gauge
	requestQueueSize   prometheus.Gauge

	// Custom metrics
	customGauges   map[string]prometheus.Gauge
	customCounters map[string]prometheus.Counter
}

// NewGatewayCollector creates a new GatewayCollector.
func NewGatewayCollector(serviceName, version string) *GatewayCollector {
	gc := &GatewayCollector{
		startTime:      time.Now(),
		customGauges:   make(map[string]prometheus.Gauge),
		customCounters: make(map[string]prometheus.Counter),
	}

	gc.gatewayInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "info",
			Help:      "Gateway information",
		},
		[]string{"service", "version", "go_version"},
	)
	gc.gatewayInfo.WithLabelValues(serviceName, version, runtime.Version()).Set(1)

	gc.uptime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "uptime_seconds",
			Help:      "Gateway uptime in seconds",
		},
	)

	gc.goroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "goroutines",
			Help:      "Current number of goroutines",
		},
	)

	gc.threads = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "threads",
			Help:      "Current number of OS threads",
		},
	)

	gc.heapAlloc = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "heap_alloc_bytes",
			Help:      "Current heap allocation in bytes",
		},
	)

	gc.heapSys = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "heap_sys_bytes",
			Help:      "Total heap memory obtained from OS",
		},
	)

	gc.gcPause = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "gc_pause_seconds",
			Help:      "GC pause duration in seconds",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1},
		},
	)

	gc.activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "active_connections",
			Help:      "Current number of active connections",
		},
	)

	gc.totalConnections = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "total_connections",
			Help:      "Total number of connections established",
		},
	)

	gc.connectionErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "connection_errors_total",
			Help:      "Total number of connection errors",
		},
	)

	gc.connectionDurations = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "connection_duration_seconds",
			Help:      "Connection duration in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 15), // 0.1s to ~3276s
		},
	)

	gc.requestsInProgress = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "requests_in_progress",
			Help:      "Current number of requests being processed",
		},
	)

	gc.requestQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "request_queue_size",
			Help:      "Current size of the request queue",
		},
	)

	return gc
}

// Collect updates all metrics. Should be called periodically.
func (gc *GatewayCollector) Collect() {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	// Update uptime
	gc.uptime.Set(time.Since(gc.startTime).Seconds())

	// Update runtime metrics
	gc.goroutines.Set(float64(runtime.NumGoroutine()))

	// Update thread count - note: this is an approximation
	// Go doesn't expose exact thread count, but GOMAXPROCS gives the max
	gc.threads.Set(float64(runtime.GOMAXPROCS(0)))

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	gc.heapAlloc.Set(float64(memStats.HeapAlloc))
	gc.heapSys.Set(float64(memStats.HeapSys))

	// Record GC pause times - fixed index calculation
	if memStats.NumGC > 0 {
		// PauseNs is a circular buffer of the last 256 GC pause times
		// The most recent pause is at index (NumGC - 1) % 256
		idx := (memStats.NumGC - 1) % 256
		pauseNs := memStats.PauseNs[idx]
		gc.gcPause.Observe(float64(pauseNs) / 1e9)
	}
}

// SetActiveConnections sets the number of active connections.
func (gc *GatewayCollector) SetActiveConnections(count int) {
	gc.activeConnections.Set(float64(count))
}

// IncrementConnections increments total connections.
func (gc *GatewayCollector) IncrementConnections() {
	gc.totalConnections.Inc()
}

// IncrementConnectionErrors increments connection errors.
func (gc *GatewayCollector) IncrementConnectionErrors() {
	gc.connectionErrors.Inc()
}

// RecordConnectionDuration records a connection duration.
func (gc *GatewayCollector) RecordConnectionDuration(duration time.Duration) {
	gc.connectionDurations.Observe(duration.Seconds())
}

// SetRequestsInProgress sets the number of requests in progress.
func (gc *GatewayCollector) SetRequestsInProgress(count int) {
	gc.requestsInProgress.Set(float64(count))
}

// IncrementRequestsInProgress increments requests in progress.
func (gc *GatewayCollector) IncrementRequestsInProgress() {
	gc.requestsInProgress.Inc()
}

// DecrementRequestsInProgress decrements requests in progress.
func (gc *GatewayCollector) DecrementRequestsInProgress() {
	gc.requestsInProgress.Dec()
}

// SetRequestQueueSize sets the request queue size.
func (gc *GatewayCollector) SetRequestQueueSize(size int) {
	gc.requestQueueSize.Set(float64(size))
}

// RegisterCustomGauge registers a custom gauge metric.
func (gc *GatewayCollector) RegisterCustomGauge(name, help string) prometheus.Gauge {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if gauge, exists := gc.customGauges[name]; exists {
		return gauge
	}

	gauge := promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      name,
			Help:      help,
		},
	)
	gc.customGauges[name] = gauge
	return gauge
}

// RegisterCustomCounter registers a custom counter metric.
func (gc *GatewayCollector) RegisterCustomCounter(name, help string) prometheus.Counter {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if counter, exists := gc.customCounters[name]; exists {
		return counter
	}

	counter := promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      name,
			Help:      help,
		},
	)
	gc.customCounters[name] = counter
	return counter
}

// GetCustomGauge returns a custom gauge by name.
func (gc *GatewayCollector) GetCustomGauge(name string) (prometheus.Gauge, bool) {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	gauge, exists := gc.customGauges[name]
	return gauge, exists
}

// GetCustomCounter returns a custom counter by name.
func (gc *GatewayCollector) GetCustomCounter(name string) (prometheus.Counter, bool) {
	gc.mu.RLock()
	defer gc.mu.RUnlock()
	counter, exists := gc.customCounters[name]
	return counter, exists
}

// RuntimeCollector collects Go runtime metrics.
type RuntimeCollector struct {
	memStats runtime.MemStats

	// Memory metrics
	allocBytes      prometheus.Gauge
	totalAllocBytes prometheus.Counter
	sysBytes        prometheus.Gauge
	mallocsTotal    prometheus.Counter
	freesTotal      prometheus.Counter

	// GC metrics
	gcSysBytes    prometheus.Gauge
	gcNextBytes   prometheus.Gauge
	gcCPUFraction prometheus.Gauge
	numGC         prometheus.Counter

	// Goroutine metrics
	numGoroutines prometheus.Gauge
	numCgoCall    prometheus.Counter
}

// NewRuntimeCollector creates a new RuntimeCollector.
func NewRuntimeCollector() *RuntimeCollector {
	rc := &RuntimeCollector{}

	rc.allocBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "alloc_bytes",
			Help:      "Number of bytes allocated and still in use",
		},
	)

	rc.totalAllocBytes = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "total_alloc_bytes_total",
			Help:      "Total number of bytes allocated (even if freed)",
		},
	)

	rc.sysBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "sys_bytes",
			Help:      "Number of bytes obtained from system",
		},
	)

	rc.mallocsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "mallocs_total",
			Help:      "Total number of mallocs",
		},
	)

	rc.freesTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "frees_total",
			Help:      "Total number of frees",
		},
	)

	rc.gcSysBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "gc_sys_bytes",
			Help:      "Number of bytes used for garbage collection system metadata",
		},
	)

	rc.gcNextBytes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "gc_next_bytes",
			Help:      "Target heap size of the next GC cycle",
		},
	)

	rc.gcCPUFraction = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "gc_cpu_fraction",
			Help:      "Fraction of CPU time used by GC",
		},
	)

	rc.numGC = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "gc_completed_total",
			Help:      "Total number of completed GC cycles",
		},
	)

	rc.numGoroutines = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "goroutines",
			Help:      "Number of goroutines",
		},
	)

	rc.numCgoCall = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Subsystem: "runtime",
			Name:      "cgo_calls_total",
			Help:      "Total number of cgo calls",
		},
	)

	return rc
}

// Collect updates all runtime metrics.
func (rc *RuntimeCollector) Collect() {
	runtime.ReadMemStats(&rc.memStats)

	rc.allocBytes.Set(float64(rc.memStats.Alloc))
	rc.sysBytes.Set(float64(rc.memStats.Sys))
	rc.gcSysBytes.Set(float64(rc.memStats.GCSys))
	rc.gcNextBytes.Set(float64(rc.memStats.NextGC))
	rc.gcCPUFraction.Set(rc.memStats.GCCPUFraction)
	rc.numGoroutines.Set(float64(runtime.NumGoroutine()))
}
