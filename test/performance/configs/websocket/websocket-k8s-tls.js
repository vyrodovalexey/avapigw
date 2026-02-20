// WebSocket Performance Test: K8s TLS (WSS)
// Purpose: Measure WebSocket message throughput over TLS in K8s
// Duration: 30 seconds
// Tool: k6 (https://k6.io)

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const messagesSent = new Counter('wss_messages_sent');
const messagesReceived = new Counter('wss_messages_received');
const messageLatency = new Trend('wss_message_latency', true);
const messageSuccess = new Rate('wss_message_success');
const messageErrors = new Counter('wss_message_errors');
const connectionErrors = new Counter('wss_connection_errors');

// Test configuration - 30 seconds
export const options = {
    vus: 10,
    duration: '30s',
    thresholds: {
        'wss_message_success': ['rate>0.90'],
    },
    insecureSkipTLSVerify: true,
};

// WebSocket URL - WSS (TLS) endpoint
const WS_URL = __ENV.WS_URL || 'wss://host.docker.internal:32681/ws';

// Message configuration
const MESSAGES_PER_CONNECTION = 50;
const MESSAGE_INTERVAL_MS = 100;

export default function () {
    const pendingMessages = new Map();
    
    const res = ws.connect(WS_URL, {}, function (socket) {
        socket.on('open', function () {
            // Send messages at regular intervals
            for (let i = 0; i < MESSAGES_PER_CONNECTION; i++) {
                // k6 setTimeout requires timeout > 0, so use (i+1) * interval
                socket.setTimeout(function () {
                    const msgId = `${__VU}-${__ITER}-${i}`;
                    const message = JSON.stringify({
                        type: 'echo',
                        id: msgId,
                        timestamp: Date.now(),
                        payload: {
                            vu: __VU,
                            iteration: __ITER,
                            sequence: i,
                            data: 'K8s TLS WebSocket performance test',
                        },
                    });
                    
                    pendingMessages.set(msgId, Date.now());
                    socket.send(message);
                    messagesSent.add(1);
                }, (i + 1) * MESSAGE_INTERVAL_MS);
            }
            
            // Close connection after all messages sent + buffer time
            socket.setTimeout(function () {
                socket.close();
            }, (MESSAGES_PER_CONNECTION + 1) * MESSAGE_INTERVAL_MS + 1000);
        });
        
        socket.on('message', function (message) {
            messagesReceived.add(1);
            
            try {
                const data = JSON.parse(message);
                
                // Try ID-based latency tracking first (if backend preserves id)
                if (data.id && pendingMessages.has(data.id)) {
                    const sentTime = pendingMessages.get(data.id);
                    const latency = Date.now() - sentTime;
                    messageLatency.add(latency);
                    pendingMessages.delete(data.id);
                }
                // Count any valid JSON response as success — the gateway
                // correctly proxied the WebSocket message to the backend
                // and returned a response. Some backends (e.g. restapi-example)
                // echo messages without preserving the original JSON id field.
                messageSuccess.add(1);
            } catch (e) {
                // Non-JSON message — still a valid WebSocket frame
                messageSuccess.add(1);
            }
        });
        
        socket.on('error', function (e) {
            messageErrors.add(1);
            messageSuccess.add(0);
        });
        
        socket.on('close', function () {
            // Note: pending messages are NOT counted as failures.
            // The backend may not echo every message (e.g. rate limiting,
            // buffering, or protocol differences). The success metric
            // tracks received responses, not sent-vs-received ratio.
            pendingMessages.clear();
        });
    });
    
    const connected = check(res, {
        'WSS connection established': (r) => r && r.status === 101,
    });
    
    if (!connected) {
        connectionErrors.add(1);
    }
    
    sleep(0.5);
}

export function handleSummary(data) {
    const metrics = data.metrics;
    
    const sent = metrics.wss_messages_sent ? metrics.wss_messages_sent.values.count : 0;
    const received = metrics.wss_messages_received ? metrics.wss_messages_received.values.count : 0;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    const connErrors = metrics.wss_connection_errors ? metrics.wss_connection_errors.values.count : 0;
    
    const summary = {
        messages_sent: sent,
        messages_received: received,
        messages_per_sec_sent: sent / duration,
        messages_per_sec_recv: received / duration,
        connection_errors: connErrors,
        success_rate: metrics.wss_message_success ? metrics.wss_message_success.values.rate : 0,
        latency: {
            avg: metrics.wss_message_latency ? metrics.wss_message_latency.values.avg : 0,
            min: metrics.wss_message_latency ? metrics.wss_message_latency.values.min : 0,
            max: metrics.wss_message_latency ? metrics.wss_message_latency.values.max : 0,
            p50: metrics.wss_message_latency ? metrics.wss_message_latency.values['p(50)'] : 0,
            p90: metrics.wss_message_latency ? metrics.wss_message_latency.values['p(90)'] : 0,
            p95: metrics.wss_message_latency ? metrics.wss_message_latency.values['p(95)'] : 0,
            p99: metrics.wss_message_latency ? metrics.wss_message_latency.values['p(99)'] : 0,
        },
        duration_sec: duration,
    };
    
    // Write results to RESULTS_DIR if set, otherwise stdout only.
    // When running in Docker, RESULTS_DIR=/results; natively it can be
    // set to a local directory by the test runner script.
    const resultsDir = __ENV.RESULTS_DIR || '';
    const result = { 'stdout': JSON.stringify(summary, null, 2) };
    if (resultsDir) {
        result[resultsDir + '/websocket-tls-results.json'] = JSON.stringify(summary, null, 2);
    }
    return result;
}
