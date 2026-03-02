// k6 GraphQL OIDC Performance Test
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const graphqlDuration = new Trend('graphql_duration', true);
const successCount = new Counter('success_count');

export const options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '2m', target: 50 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],
    errors: ['rate<0.15'],
  },
  insecureSkipTLSVerify: true,
};

const GATEWAY_URL = 'https://host.docker.internal:30205/graphql';
const KEYCLOAK_URL = 'http://host.docker.internal:8090/realms/gateway-test/protocol/openid-connect/token';

let cachedToken = null;
let tokenExpiry = 0;

function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiry) {
    return cachedToken;
  }

  const tokenRes = http.post(KEYCLOAK_URL, {
    grant_type: 'password',
    client_id: 'gateway',
    client_secret: 'gateway-secret',
    username: 'testuser',
    password: 'testpass',
  });

  if (tokenRes.status === 200) {
    const body = JSON.parse(tokenRes.body);
    cachedToken = body.access_token;
    tokenExpiry = now + (body.expires_in - 30) * 1000; // refresh 30s before expiry
  }

  return cachedToken;
}

const queries = [
  '{ items { id name description price quantity category } }',
  '{ item(id: "1") { id name price } }',
];

export default function () {
  const token = getToken();
  if (!token) {
    errorRate.add(true);
    return;
  }

  const query = queries[Math.floor(Math.random() * queries.length)];
  const payload = JSON.stringify({ query: query });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Host': 'avapigw.local',
      'Accept': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
  };

  const res = http.post(GATEWAY_URL, payload, params);

  const success = check(res, {
    'status is 200': (r) => r.status === 200,
    'has data': (r) => {
      try { return JSON.parse(r.body).data !== undefined; } catch (e) { return false; }
    },
  });

  errorRate.add(!success);
  if (success) successCount.add(1);
  graphqlDuration.add(res.timings.duration);
}
