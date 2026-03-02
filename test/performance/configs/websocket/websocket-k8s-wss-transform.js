// WebSocket Performance Test: K8s WSS with Header Transform (3 minutes)
// Purpose: Measure WebSocket message throughput with header transformation over TLS
// Duration: 3 minutes
// Tool: k6

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// Custom metrics
const messagesSent = new Counter('wss_transform_messages_sent');
const messagesReceived = new Counter('wss_transform_messages_received');
const messageLatency = new Trend('wss_transform_message_latency', true);
const messageSuccess = new Rate('wss_transform_message_success');
const messageErrors = new Counter('wss_transform_message_errors');
const connectionErrors = new Counter('wss_transform_connection_errors');

// Test configuration - 3 minutes
export const options = {
    stages: [
        { duration: '30s', target: 20 },   // ramp up
        { duration: '2m', target: 20 },     // sustain
        { duration: '30s', target: 0 },     // ramp down
    ],
    thresholds: {
        'wss_transform_message_success': ['rate>0.80'],
    },
    insecureSkipTLSVerify: true,
};

// WebSocket URL - WSS endpoint via K8s NodePort
const WS_URL = __ENV.WS_URL || 'wss://host.docker.internal:30205/ws-perf-transform';

// Message configuration
const MESSAGES_PER_CONNECTION = 30;
const MESSAGE_INTERVAL_MS = 200;

export default function () {
    const pendingMessages = new Map();

    const res = ws.connect(WS_URL, {
        headers: {
            'X-Perf-Test': 'ws-transform',
        },
    }, function (socket) {
        socket.on('open', function () {
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
                            data: 'K8s WSS Transform performance test message',
                        },
                    });

                    pendingMessages.set(msgId, Date.now());
                    socket.send(message);
                    messagesSent.add(1);
                }, (i + 1) * MESSAGE_INTERVAL_MS);
            }

            socket.setTimeout(function () {
                socket.close();
            }, (MESSAGES_PER_CONNECTION + 1) * MESSAGE_INTERVAL_MS + 2000);
        });

        socket.on('message', function (message) {
            messagesReceived.add(1);

            try {
                const data = JSON.parse(message);
                if (data.id && pendingMessages.has(data.id)) {
                    const sentTime = pendingMessages.get(data.id);
                    const latency = Date.now() - sentTime;
                    messageLatency.add(latency);
                    pendingMessages.delete(data.id);
                }
                messageSuccess.add(1);
            } catch (e) {
                messageSuccess.add(1);
            }
        });

        socket.on('error', function (e) {
            messageErrors.add(1);
            messageSuccess.add(0);
        });

        socket.on('close', function () {
            pendingMessages.clear();
        });
    });

    const connected = check(res, {
        'WSS Transform connection established': (r) => r && r.status === 101,
    });

    if (!connected) {
        connectionErrors.add(1);
    }

    sleep(0.5);
}

export function handleSummary(data) {
    const metrics = data.metrics;

    const sent = metrics.wss_transform_messages_sent ? metrics.wss_transform_messages_sent.values.count : 0;
    const received = metrics.wss_transform_messages_received ? metrics.wss_transform_messages_received.values.count : 0;
    const duration = data.state ? data.state.testRunDurationMs / 1000 : 1;
    const connErrors = metrics.wss_transform_connection_errors ? metrics.wss_transform_connection_errors.values.count : 0;

    const summary = {
        test: 'wss-transform',
        messages_sent: sent,
        messages_received: received,
        messages_per_sec_sent: sent / duration,
        messages_per_sec_recv: received / duration,
        connection_errors: connErrors,
        success_rate: metrics.wss_transform_message_success ? metrics.wss_transform_message_success.values.rate : 0,
        latency: {
            avg: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values.avg : 0,
            min: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values.min : 0,
            max: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values.max : 0,
            p50: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values['p(50)'] : 0,
            p90: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values['p(90)'] : 0,
            p95: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values['p(95)'] : 0,
            p99: metrics.wss_transform_message_latency ? metrics.wss_transform_message_latency.values['p(99)'] : 0,
        },
        duration_sec: duration,
    };

    const result = { 'stdout': JSON.stringify(summary, null, 2) };
    result['/results/wss-transform-results.json'] = JSON.stringify(summary, null, 2);
    return result;
}
