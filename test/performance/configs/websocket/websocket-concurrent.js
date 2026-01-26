// WebSocket Performance Test: Concurrent Connections
// Purpose: Measure maximum concurrent WebSocket connections
// Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
// Target: 2000+ concurrent connections
// Tool: k6 (https://k6.io)

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend, Gauge } from 'k6/metrics';

// Custom metrics
const activeConnections = new Gauge('ws_active_connections');
const peakConnections = new Gauge('ws_peak_connections');
const connectionTime = new Trend('ws_connection_time', true);
const connectionSuccess = new Rate('ws_connection_success');
const connectionErrors = new Counter('ws_connection_errors');
const messagesExchanged = new Counter('ws_messages_exchanged');
const connectionDuration = new Trend('ws_connection_duration', true);

// Track active connections globally
let currentActive = 0;
let maxActive = 0;

// Test configuration - 5 minutes total with 2000+ concurrent connections target
export const options = {
    scenarios: {
        // Gradually increase concurrent connections
        concurrent_connections: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '1m', target: 500 },    // Warmup: ramp to 500 concurrent
                { duration: '30s', target: 1000 },  // Ramp to 1000 concurrent
                { duration: '30s', target: 2000 },  // Ramp to 2000 concurrent
                { duration: '2m', target: 2000 },   // Sustain: hold at 2000
                { duration: '1m', target: 0 },      // Cooldown: ramp down
            ],
            gracefulRampDown: '30s',
        },
    },
    thresholds: {
        'ws_connection_success': ['rate>0.90'],     // 90% success rate
        'ws_connection_time': ['p(95)<2000'],       // 95% connect under 2s
        'ws_peak_connections': ['value>=2000'],     // Achieve 2000+ concurrent
    },
};

// WebSocket URL
const WS_URL = __ENV.WS_URL || 'ws://host.docker.internal:8080/ws';

// Connection hold time (how long to keep each connection open)
const CONNECTION_HOLD_TIME = 60000; // 60 seconds for concurrent test
const PING_INTERVAL = 10000; // 10 seconds

export default function () {
    const startTime = Date.now();
    let connected = false;
    let messageCount = 0;
    
    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'websocket-concurrent',
            'X-Request-ID': `conc-${__VU}-${__ITER}`,
        },
    }, function (socket) {
        const connectTime = Date.now() - startTime;
        connectionTime.add(connectTime);
        
        socket.on('open', function () {
            connected = true;
            connectionSuccess.add(1);
            
            // Track active connections
            currentActive++;
            if (currentActive > maxActive) {
                maxActive = currentActive;
            }
            activeConnections.add(currentActive);
            peakConnections.add(maxActive);
            
            // Send initial message
            socket.send(JSON.stringify({
                type: 'connect',
                vu: __VU,
                iteration: __ITER,
                timestamp: Date.now(),
            }));
            messageCount++;
            
            // Set up periodic ping to keep connection alive
            const pingInterval = setInterval(function () {
                if (socket.readyState === 1) { // OPEN
                    socket.send(JSON.stringify({
                        type: 'ping',
                        timestamp: Date.now(),
                    }));
                    messageCount++;
                }
            }, PING_INTERVAL);
            
            // Close connection after hold time
            socket.setTimeout(function () {
                clearInterval(pingInterval);
                socket.close();
            }, CONNECTION_HOLD_TIME);
        });
        
        socket.on('message', function (message) {
            messagesExchanged.add(1);
            
            try {
                const data = JSON.parse(message);
                check(data, {
                    'message is valid': (d) => d !== null,
                });
            } catch (e) {
                // Non-JSON message
            }
        });
        
        socket.on('error', function (e) {
            connectionErrors.add(1);
            if (!connected) {
                connectionSuccess.add(0);
            }
            console.error(`WebSocket error (VU ${__VU}): ${e.error()}`);
        });
        
        socket.on('close', function () {
            if (connected) {
                currentActive--;
                activeConnections.add(currentActive);
                
                const duration = Date.now() - startTime;
                connectionDuration.add(duration);
                
                messagesExchanged.add(messageCount);
            }
        });
    });
    
    check(res, {
        'WebSocket connection established': (r) => r && r.status === 101,
    });
    
    if (!res || res.status !== 101) {
        connectionErrors.add(1);
        connectionSuccess.add(0);
    }
    
    // Wait for connection to complete before starting next iteration
    sleep(CONNECTION_HOLD_TIME / 1000 + 1);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: '  ', enableColors: true }),
        '/results/websocket-concurrent-results.json': JSON.stringify(data, null, 2),
    };
}

function textSummary(data, options) {
    const metrics = data.metrics;
    
    const totalConnections = metrics.ws_connection_time ? metrics.ws_connection_time.values.count : 0;
    const successRate = metrics.ws_connection_success ? metrics.ws_connection_success.values.rate * 100 : 0;
    const errors = metrics.ws_connection_errors ? metrics.ws_connection_errors.values.count : 0;
    const messages = metrics.ws_messages_exchanged ? metrics.ws_messages_exchanged.values.count : 0;
    const peak = metrics.ws_peak_connections ? metrics.ws_peak_connections.values.value : 0;
    
    let summary = `
================================================================================
WebSocket Concurrent Connections Test Results
================================================================================

Connection Statistics:
  Total Connections:     ${totalConnections}
  Peak Concurrent:       ${peak}
  Success Rate:          ${successRate.toFixed(2)}%
  Connection Errors:     ${errors}
  Messages Exchanged:    ${messages}

Connection Time (ms):
  Average:               ${metrics.ws_connection_time ? metrics.ws_connection_time.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values.min.toFixed(2) : 0}
  Max:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values.max.toFixed(2) : 0}
  P90:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(90)'].toFixed(2) : 0}
  P95:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(95)'].toFixed(2) : 0}
  P99:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(99)'].toFixed(2) : 0}

Connection Duration (ms):
  Average:               ${metrics.ws_connection_duration ? metrics.ws_connection_duration.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.ws_connection_duration ? metrics.ws_connection_duration.values.min.toFixed(2) : 0}
  Max:                   ${metrics.ws_connection_duration ? metrics.ws_connection_duration.values.max.toFixed(2) : 0}

================================================================================
`;
    
    return summary;
}
