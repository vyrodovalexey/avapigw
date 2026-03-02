// k6 GraphQL API Key Performance Test
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

const queries = [
  '{ items { id name description price quantity category } }',
  '{ item(id: "1") { id name price } }',
];

export default function () {
  const query = queries[Math.floor(Math.random() * queries.length)];
  const payload = JSON.stringify({ query: query });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Host': 'avapigw.local',
      'Accept': 'application/json',
      'X-API-Key': 'pk_perftest_1234567890abcdef',
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
