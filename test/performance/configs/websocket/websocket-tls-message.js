// WebSocket Performance Test: Message Throughput with TLS (WSS)
// Purpose: Measure WebSocket message throughput over TLS
// Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
// Target: 2000+ messages/second
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
const bytesTransferred = new Counter('wss_bytes_transferred');
const tlsHandshakeTime = new Trend('wss_tls_handshake_time', true);

// Test configuration - 5 minutes total with 2000+ messages/second target
export const options = {
    scenarios: {
        message_throughput_tls: {
            executor: 'ramping-vus',
            startVUs: 10,
            stages: [
                { duration: '1m', target: 100 },   // Warmup: ramp to 100 VUs
                { duration: '3m', target: 100 },   // Sustain: hold at 100 VUs
                { duration: '1m', target: 10 },    // Cooldown: ramp down
            ],
            gracefulRampDown: '30s',
        },
    },
    thresholds: {
        'wss_message_latency': ['p(95)<150'],    // 95% of messages under 150ms (higher for TLS)
        'wss_message_success': ['rate>0.99'],    // 99% success rate
        'wss_messages_sent': ['count>600000'],   // At least 600k messages
    },
    // TLS configuration
    tlsAuth: [
        {
            // Skip certificate verification for self-signed certs in test environment
            // In production, use proper CA certificates
        }
    ],
    insecureSkipTLSVerify: true,
};

// WebSocket URL - WSS (TLS) endpoint
const WS_URL = __ENV.WS_URL || 'wss://host.docker.internal:8443/ws';

// Message configuration
const MESSAGES_PER_CONNECTION = 200;
const MESSAGE_INTERVAL_MS = 50;

export default function () {
    const pendingMessages = new Map();
    let receivedCount = 0;
    const connectionStartTime = Date.now();
    
    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'websocket-tls-message',
            'X-Request-ID': `wss-msg-${__VU}-${__ITER}`,
        },
    }, function (socket) {
        socket.on('open', function () {
            // Record TLS handshake time (approximate)
            const handshakeTime = Date.now() - connectionStartTime;
            tlsHandshakeTime.add(handshakeTime);
            
            // Send messages at regular intervals
            for (let i = 0; i < MESSAGES_PER_CONNECTION; i++) {
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
                            data: 'TLS encrypted performance test message payload',
                            tls: true,
                        },
                    });
                    
                    pendingMessages.set(msgId, Date.now());
                    socket.send(message);
                    messagesSent.add(1);
                    bytesTransferred.add(message.length);
                }, i * MESSAGE_INTERVAL_MS);
            }
            
            // Close connection after all messages sent + buffer time
            socket.setTimeout(function () {
                socket.close();
            }, MESSAGES_PER_CONNECTION * MESSAGE_INTERVAL_MS + 2000);
        });
        
        socket.on('message', function (message) {
            messagesReceived.add(1);
            receivedCount++;
            bytesTransferred.add(message.length);
            
            try {
                const data = JSON.parse(message);
                
                if (data.id && pendingMessages.has(data.id)) {
                    const sentTime = pendingMessages.get(data.id);
                    const latency = Date.now() - sentTime;
                    messageLatency.add(latency);
                    messageSuccess.add(1);
                    pendingMessages.delete(data.id);
                }
                
                check(data, {
                    'response has id': (d) => d.id !== undefined,
                    'response has type': (d) => d.type !== undefined,
                });
            } catch (e) {
                // Non-JSON message
            }
        });
        
        socket.on('error', function (e) {
            messageErrors.add(1);
            messageSuccess.add(0);
            console.error(`WSS error: ${e.error()}`);
        });
        
        socket.on('close', function () {
            pendingMessages.forEach((_, msgId) => {
                messageSuccess.add(0);
            });
        });
    });
    
    check(res, {
        'WSS connection established': (r) => r && r.status === 101,
    });
    
    sleep(0.5);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: '  ', enableColors: true }),
        '/results/websocket-tls-message-results.json': JSON.stringify(data, null, 2),
    };
}

function textSummary(data, options) {
    const metrics = data.metrics;
    
    const sent = metrics.wss_messages_sent ? metrics.wss_messages_sent.values.count : 0;
    const received = metrics.wss_messages_received ? metrics.wss_messages_received.values.count : 0;
    const bytes = metrics.wss_bytes_transferred ? metrics.wss_bytes_transferred.values.count : 0;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    
    let summary = `
================================================================================
WebSocket TLS (WSS) Message Throughput Test Results
================================================================================

Message Statistics:
  Messages Sent:         ${sent}
  Messages Received:     ${received}
  Messages/sec (sent):   ${(sent / duration).toFixed(2)}
  Messages/sec (recv):   ${(received / duration).toFixed(2)}
  Bytes Transferred:     ${(bytes / 1024 / 1024).toFixed(2)} MB
  Throughput:            ${(bytes / duration / 1024).toFixed(2)} KB/s

TLS Handshake Time (ms):
  Average:               ${metrics.wss_tls_handshake_time ? metrics.wss_tls_handshake_time.values.avg.toFixed(2) : 0}
  P95:                   ${metrics.wss_tls_handshake_time ? metrics.wss_tls_handshake_time.values['p(95)'].toFixed(2) : 0}

Success Rate:
  Message Success:       ${metrics.wss_message_success ? (metrics.wss_message_success.values.rate * 100).toFixed(2) : 0}%
  Message Errors:        ${metrics.wss_message_errors ? metrics.wss_message_errors.values.count : 0}

Message Latency (ms):
  Average:               ${metrics.wss_message_latency ? metrics.wss_message_latency.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values.min.toFixed(2) : 0}
  Max:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values.max.toFixed(2) : 0}
  P50:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values['p(50)'].toFixed(2) : 0}
  P90:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values['p(90)'].toFixed(2) : 0}
  P95:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values['p(95)'].toFixed(2) : 0}
  P99:                   ${metrics.wss_message_latency ? metrics.wss_message_latency.values['p(99)'].toFixed(2) : 0}

================================================================================
`;
    
    return summary;
}
