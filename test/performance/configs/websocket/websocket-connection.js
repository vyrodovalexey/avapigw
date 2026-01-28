// WebSocket Performance Test: Connection Throughput
// Purpose: Measure WebSocket connection establishment throughput
// Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
// Target: 2000+ connections/second
// Tool: k6 (https://k6.io)

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const connectionTime = new Trend('ws_connection_time', true);
const connectionSuccess = new Rate('ws_connection_success');
const connectionErrors = new Counter('ws_connection_errors');
const messagesReceived = new Counter('ws_messages_received');
const totalConnections = new Counter('ws_total_connections');

// Test configuration - 5 minutes total with 2000+ connections/second target
export const options = {
    scenarios: {
        // Ramp up connections over time
        connection_test: {
            executor: 'ramping-vus',
            startVUs: 10,
            stages: [
                { duration: '1m', target: 200 },   // Warmup: ramp to 200 VUs
                { duration: '3m', target: 200 },   // Sustain: hold at 200 VUs
                { duration: '1m', target: 10 },    // Cooldown: ramp down
            ],
            gracefulRampDown: '10s',
        },
    },
    thresholds: {
        'ws_connection_time': ['p(95)<1000'],  // 95% of connections under 1s
        'ws_connection_success': ['rate>0.95'], // 95% success rate
        'ws_total_connections': ['count>600000'], // At least 600k connections
    },
};

// WebSocket URL - adjust based on gateway configuration
const WS_URL = __ENV.WS_URL || 'ws://host.docker.internal:8080/ws';

export default function () {
    const startTime = Date.now();
    
    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'websocket-connection',
            'X-Request-ID': `conn-${__VU}-${__ITER}`,
        },
    }, function (socket) {
        const connectTime = Date.now() - startTime;
        connectionTime.add(connectTime);
        totalConnections.add(1);
        
        socket.on('open', function () {
            connectionSuccess.add(1);
            
            // Send a ping message
            socket.send(JSON.stringify({
                type: 'ping',
                timestamp: Date.now(),
                vu: __VU,
                iteration: __ITER,
            }));
        });
        
        socket.on('message', function (message) {
            messagesReceived.add(1);
            
            // Verify message is valid JSON
            try {
                const data = JSON.parse(message);
                check(data, {
                    'message has type': (d) => d.type !== undefined,
                });
            } catch (e) {
                // Binary or non-JSON message
            }
        });
        
        socket.on('error', function (e) {
            connectionErrors.add(1);
            connectionSuccess.add(0);
            console.error(`WebSocket error: ${e.error()}`);
        });
        
        socket.on('close', function () {
            // Connection closed
        });
        
        // Keep connection open briefly
        socket.setTimeout(function () {
            socket.close();
        }, 500);  // Shorter hold time for connection throughput test
    });
    
    // Check connection result
    check(res, {
        'WebSocket connection established': (r) => r && r.status === 101,
    });
    
    if (!res || res.status !== 101) {
        connectionErrors.add(1);
        connectionSuccess.add(0);
    }
    
    // Minimal delay between iterations for high throughput
    sleep(0.05);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: '  ', enableColors: true }),
        '/results/websocket-connection-results.json': JSON.stringify(data, null, 2),
    };
}

function textSummary(data, options) {
    const metrics = data.metrics;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    const totalConns = metrics.ws_total_connections ? metrics.ws_total_connections.values.count : 0;
    
    let summary = `
================================================================================
WebSocket Connection Test Results
================================================================================

Connection Metrics:
  Total Connections:     ${totalConns}
  Connections/sec:       ${(totalConns / duration).toFixed(2)}
  Success Rate:          ${metrics.ws_connection_success ? (metrics.ws_connection_success.values.rate * 100).toFixed(2) : 0}%
  Connection Errors:     ${metrics.ws_connection_errors ? metrics.ws_connection_errors.values.count : 0}
  Messages Received:     ${metrics.ws_messages_received ? metrics.ws_messages_received.values.count : 0}

Connection Time (ms):
  Average:               ${metrics.ws_connection_time ? metrics.ws_connection_time.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values.min.toFixed(2) : 0}
  Max:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values.max.toFixed(2) : 0}
  P90:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(90)'].toFixed(2) : 0}
  P95:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(95)'].toFixed(2) : 0}
  P99:                   ${metrics.ws_connection_time ? metrics.ws_connection_time.values['p(99)'].toFixed(2) : 0}

================================================================================
`;
    
    return summary;
}
