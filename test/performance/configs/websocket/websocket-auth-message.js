// WebSocket Performance Test: Message Throughput with JWT Authentication
// Purpose: Measure WebSocket message throughput with JWT auth
// Duration: 5 minutes (1m warmup + 3m sustain + 1m cooldown)
// Target: 2000+ messages/second
// Tool: k6 (https://k6.io)
// Note: Requires valid JWT token from Keycloak

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import http from 'k6/http';

// Custom metrics
const messagesSent = new Counter('ws_auth_messages_sent');
const messagesReceived = new Counter('ws_auth_messages_received');
const messageLatency = new Trend('ws_auth_message_latency', true);
const messageSuccess = new Rate('ws_auth_message_success');
const messageErrors = new Counter('ws_auth_message_errors');
const bytesTransferred = new Counter('ws_auth_bytes_transferred');
const authTime = new Trend('ws_auth_time', true);
const authErrors = new Counter('ws_auth_errors');

// Test configuration - 5 minutes total with 2000+ messages/second target
export const options = {
    scenarios: {
        message_throughput_auth: {
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
        'ws_auth_message_latency': ['p(95)<150'],  // 95% of messages under 150ms
        'ws_auth_message_success': ['rate>0.99'],  // 99% success rate
        'ws_auth_messages_sent': ['count>600000'], // At least 600k messages
        'ws_auth_time': ['p(95)<500'],             // Auth should complete in 500ms
    },
};

// Keycloak configuration
const KEYCLOAK_URL = __ENV.KEYCLOAK_URL || 'http://host.docker.internal:8090';
const KEYCLOAK_REALM = __ENV.KEYCLOAK_REALM || 'gateway-test';
const KEYCLOAK_CLIENT_ID = __ENV.KEYCLOAK_CLIENT_ID || 'gateway';
const KEYCLOAK_CLIENT_SECRET = __ENV.KEYCLOAK_CLIENT_SECRET || 'gateway-secret';

// WebSocket URL - protected endpoint requiring auth
const WS_URL = __ENV.WS_URL || 'ws://host.docker.internal:8080/ws/protected';

// Message configuration
const MESSAGES_PER_CONNECTION = 200;
const MESSAGE_INTERVAL_MS = 50;

// Token cache (per VU)
let cachedToken = null;
let tokenExpiry = 0;

// Get JWT token from Keycloak
function getToken() {
    const now = Date.now();
    
    // Return cached token if still valid (with 30s buffer)
    if (cachedToken && tokenExpiry > now + 30000) {
        return cachedToken;
    }
    
    const authStartTime = Date.now();
    
    const tokenUrl = `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`;
    
    const response = http.post(tokenUrl, {
        grant_type: 'client_credentials',
        client_id: KEYCLOAK_CLIENT_ID,
        client_secret: KEYCLOAK_CLIENT_SECRET,
    }, {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    });
    
    authTime.add(Date.now() - authStartTime);
    
    if (response.status !== 200) {
        authErrors.add(1);
        console.error(`Failed to get token: ${response.status} - ${response.body}`);
        return null;
    }
    
    try {
        const tokenData = JSON.parse(response.body);
        cachedToken = tokenData.access_token;
        // Set expiry based on expires_in (usually 300 seconds)
        tokenExpiry = now + (tokenData.expires_in * 1000);
        return cachedToken;
    } catch (e) {
        authErrors.add(1);
        console.error(`Failed to parse token response: ${e}`);
        return null;
    }
}

export default function () {
    // Get JWT token
    const token = getToken();
    if (!token) {
        messageErrors.add(1);
        messageSuccess.add(0);
        sleep(1);
        return;
    }
    
    const pendingMessages = new Map();
    let receivedCount = 0;
    
    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'websocket-auth-message',
            'X-Request-ID': `ws-auth-${__VU}-${__ITER}`,
            'Authorization': `Bearer ${token}`,
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
                            data: 'Authenticated WebSocket performance test message',
                            authenticated: true,
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
            console.error(`WebSocket auth error: ${e.error()}`);
        });
        
        socket.on('close', function () {
            pendingMessages.forEach((_, msgId) => {
                messageSuccess.add(0);
            });
        });
    });
    
    check(res, {
        'Authenticated WebSocket connection established': (r) => r && r.status === 101,
    });
    
    if (!res || res.status !== 101) {
        messageErrors.add(1);
        messageSuccess.add(0);
    }
    
    sleep(0.5);
}

export function handleSummary(data) {
    return {
        'stdout': textSummary(data, { indent: '  ', enableColors: true }),
        '/results/websocket-auth-message-results.json': JSON.stringify(data, null, 2),
    };
}

function textSummary(data, options) {
    const metrics = data.metrics;
    
    const sent = metrics.ws_auth_messages_sent ? metrics.ws_auth_messages_sent.values.count : 0;
    const received = metrics.ws_auth_messages_received ? metrics.ws_auth_messages_received.values.count : 0;
    const bytes = metrics.ws_auth_bytes_transferred ? metrics.ws_auth_bytes_transferred.values.count : 0;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    
    let summary = `
================================================================================
WebSocket Authenticated Message Throughput Test Results
================================================================================

Authentication:
  Auth Time (avg):       ${metrics.ws_auth_time ? metrics.ws_auth_time.values.avg.toFixed(2) : 0} ms
  Auth Time (p95):       ${metrics.ws_auth_time ? metrics.ws_auth_time.values['p(95)'].toFixed(2) : 0} ms
  Auth Errors:           ${metrics.ws_auth_errors ? metrics.ws_auth_errors.values.count : 0}

Message Statistics:
  Messages Sent:         ${sent}
  Messages Received:     ${received}
  Messages/sec (sent):   ${(sent / duration).toFixed(2)}
  Messages/sec (recv):   ${(received / duration).toFixed(2)}
  Bytes Transferred:     ${(bytes / 1024 / 1024).toFixed(2)} MB
  Throughput:            ${(bytes / duration / 1024).toFixed(2)} KB/s

Success Rate:
  Message Success:       ${metrics.ws_auth_message_success ? (metrics.ws_auth_message_success.values.rate * 100).toFixed(2) : 0}%
  Message Errors:        ${metrics.ws_auth_message_errors ? metrics.ws_auth_message_errors.values.count : 0}

Message Latency (ms):
  Average:               ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values.avg.toFixed(2) : 0}
  Min:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values.min.toFixed(2) : 0}
  Max:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values.max.toFixed(2) : 0}
  P50:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values['p(50)'].toFixed(2) : 0}
  P90:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values['p(90)'].toFixed(2) : 0}
  P95:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values['p(95)'].toFixed(2) : 0}
  P99:                   ${metrics.ws_auth_message_latency ? metrics.ws_auth_message_latency.values['p(99)'].toFixed(2) : 0}

================================================================================
`;
    
    return summary;
}
