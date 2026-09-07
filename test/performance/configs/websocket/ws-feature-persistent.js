// Persistent-connection WebSocket/WSS feature perf test - 180s.
// Each VU opens ONE long-lived connection and streams messages for ~170s, then
// closes. This avoids the reconnect dial-storm that exhausts Docker Desktop
// vpnkit ephemeral ports on the published-port inbound path (see PT report),
// while still exercising the gateway WS proxy + per-route auth under sustained
// message load. Env: WS_URL (required), WS_HEADER (optional "Name: value"),
// WS_VUS (default 15).
import ws from 'k6/ws';
import { check } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

const messagesSent = new Counter('ws_messages_sent');
const messagesReceived = new Counter('ws_messages_received');
const messageLatency = new Trend('ws_message_latency', true);
const messageSuccess = new Rate('ws_message_success');
const connectionErrors = new Counter('ws_connection_errors');

const VUS = parseInt(__ENV.WS_VUS || '15');
const HOLD_MS = parseInt(__ENV.WS_HOLD_MS || '168000');   // ~2m48s streaming
const MSG_INTERVAL_MS = parseInt(__ENV.WS_MSG_INTERVAL_MS || '50');

export const options = {
  scenarios: {
    persistent: {
      executor: 'constant-vus',
      vus: VUS,
      duration: '180s',
      gracefulStop: '10s',
    },
  },
  thresholds: { 'ws_message_success': ['rate>0.80'] },
  insecureSkipTLSVerify: true,
};

const WS_URL = __ENV.WS_URL || 'wss://127.0.0.1:8443/ws';

function buildParams() {
  const params = { headers: {} };
  if (__ENV.WS_HEADER) {
    const idx = __ENV.WS_HEADER.indexOf(':');
    if (idx > 0) {
      params.headers[__ENV.WS_HEADER.slice(0, idx).trim()] = __ENV.WS_HEADER.slice(idx + 1).trim();
    }
  }
  return params;
}

export default function () {
  const pending = new Map();
  const res = ws.connect(WS_URL, buildParams(), function (socket) {
    socket.on('open', function () {
      // Stream a message every MSG_INTERVAL_MS for the whole hold window.
      socket.setInterval(function () {
        const id = `${__VU}-${Date.now()}`;
        pending.set(id, Date.now());
        socket.send(JSON.stringify({ type: 'echo', id: id, payload: 'ws perf test' }));
        messagesSent.add(1);
        if (pending.size > 2000) pending.clear();
      }, MSG_INTERVAL_MS);
      socket.setTimeout(function () { socket.close(); }, HOLD_MS);
    });
    socket.on('message', function (m) {
      messagesReceived.add(1);
      try {
        const d = JSON.parse(m);
        if (d.id && pending.has(d.id)) {
          messageLatency.add(Date.now() - pending.get(d.id));
          pending.delete(d.id);
        }
      } catch (e) { /* non-JSON echo */ }
      messageSuccess.add(1);
    });
    socket.on('error', function () { messageSuccess.add(0); });
  });
  if (!check(res, { 'status 101': (r) => r && r.status === 101 })) {
    connectionErrors.add(1);
  }
}

export function handleSummary(data) {
  const m = data.metrics;
  const v = (n, f) => (m[n] && m[n].values[f] !== undefined ? m[n].values[f] : 0);
  const dur = data.state ? data.state.testRunDurationMs / 1000 : 1;
  const summary = {
    duration_sec: Math.round(dur),
    messages_sent: v('ws_messages_sent', 'count'),
    messages_received: v('ws_messages_received', 'count'),
    msgs_per_sec_recv: Math.round(v('ws_messages_received', 'count') / dur),
    connection_errors: v('ws_connection_errors', 'count'),
    success_rate: v('ws_message_success', 'rate'),
    sessions: v('ws_sessions', 'count'),
    connect_ms: { avg: v('ws_connecting', 'avg'), p95: v('ws_connecting', 'p(95)') },
    msg_latency_ms: {
      avg: v('ws_message_latency', 'avg'), p50: v('ws_message_latency', 'p(50)'),
      p95: v('ws_message_latency', 'p(95)'), p99: v('ws_message_latency', 'p(99)'),
    },
  };
  const out = (__ENV.WS_OUT || '/tmp/ws-result') + '.json';
  return { 'stdout': JSON.stringify(summary, null, 2) + '\n', [out]: JSON.stringify(summary, null, 2) };
}
