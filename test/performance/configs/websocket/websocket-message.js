// WebSocket Performance Test: Message Throughput
// Purpose: Measure WebSocket message sending/receiving throughput
// Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
// Target: 2000+ messages/second
// Tool: k6 (https://k6.io)

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const messagesSent = new Counter('ws_messages_sent');
const messagesReceived = new Counter('ws_messages_received');
const messageLatency = new Trend('ws_message_latency', true);
const messageSuccess = new Rate('ws_message_success');
const messageErrors = new Counter('ws_message_errors');
const bytesTransferred = new Counter('ws_bytes_transferred');

// Test configuration - 5 minutes total with 2000+ messages/second target
export const options = {
    scenarios: {
        message_throughput: {
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
        'ws_message_latency': ['p(95)<100'],    // 95% of messages under 100ms
        'ws_message_success': ['rate>0.99'],    // 99% success rate
        'ws_messages_sent': ['count>600000'],   // At least 600k messages (2000/s * 300s)
    },
};

// WebSocket URL
const WS_URL = __ENV.WS_URL || 'ws://host.docker.internal:8080/ws';

// Message configuration - send 20 messages per second per VU to achieve 2000+ total
const MESSAGES_PER_CONNECTION = 200;
const MESSAGE_INTERVAL_MS = 50;  // 20 messages/second per VU

export default function () {
    const pendingMessages = new Map();
    let receivedCount = 0;
    
    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'websocket-message',
            'X-Request-ID': `msg-${__VU}-${__ITER}`,
        },
    }, function (socket) {
        socket.on('open', function () {
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
                            data: 'Performance test message payload with some content for throughput measurement',
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
                
                // Calculate latency if this is a response to our message
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
            console.error(`WebSocket error: ${e.error()}`);
        });
        
        socket.on('close', function () {
            // Mark any pending messages as failed
            pendingMessages.forEach((_, msgId) => {
                messageSuccess.add(0);
            });
        });
    });
    
    check(res, {
        'WebSocket connection established': (r) => r && r.status === 101,
    });
    
    // Small delay between iterations
    sleep(0.5);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: '  ', enableColors: true }),
        '/results/websocket-message-results.json': JSON.stringify(data, null, 2),
    };
}

function textSummary(data, options) {
    const metrics = data.metrics;
    
    const sent = metrics.ws_messages_sent ? metrics.ws_messages_sent.values.count : 0;
    const received = metrics.ws_messages_received ? metrics.ws_messages_received.values.count : 0;
    const bytes = metrics.ws_bytes_transferred ? metrics.ws_bytes_transferred.values.count : 0;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    
    let summary = `
================================================================================
WebSocket Message Throughput Test Results
================================================================================

Message Statistics:
  Messages Sent:         ${sent}
  Messages Received:     ${received}
  Messages/sec (sent):   ${(sent / duration).toFixed(2)}
  Messages/sec (recv):   ${(received / duration).toFixed(2)}
  Bytes Transferred:     ${(bytes / 1024 / 1024).toFixed(2)} MB
  Throughput:            ${(bytes / duration / 1024).toFixed(2)} KB/s

Success Rate:
  Message Success:       ${metrics.ws_message_success ? (metrics.ws_message_success.values.rate * 100).toFixed(2) : 0}%
  Message Errors:        ${metrics.ws_message_errors ? metrics.ws_message_errors.values.count : 0}

Message Latency (ms):
  Average:               ${metrics.ws_message_latency ? metrics.ws_message_latency.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values.min.toFixed(2) : 0}
  Max:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values.max.toFixed(2) : 0}
  P50:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values['p(50)'].toFixed(2) : 0}
  P90:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values['p(90)'].toFixed(2) : 0}
  P95:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values['p(95)'].toFixed(2) : 0}
  P99:                   ${metrics.ws_message_latency ? metrics.ws_message_latency.values['p(99)'].toFixed(2) : 0}

================================================================================
`;
    
    return summary;
}
