// k6 GraphQL Rate Limit Performance Test
import http from 'k6/http';
import { check } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const graphqlDuration = new Trend('graphql_duration', true);
const successCount = new Counter('success_count');
const rateLimitedCount = new Counter('rate_limited');

export const options = {
  stages: [
    { duration: '30s', target: 100 },   // ramp up aggressively
    { duration: '2m', target: 100 },    // steady state - high load to trigger rate limiting
    { duration: '30s', target: 0 },     // ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],
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
    },
  };

  const res = http.post(GATEWAY_URL, payload, params);

  const isSuccess = res.status === 200;
  const isRateLimited = res.status === 429;

  check(res, {
    'status is 200 or 429': (r) => r.status === 200 || r.status === 429,
  });

  if (isRateLimited) rateLimitedCount.add(1);
  errorRate.add(!isSuccess && !isRateLimited);
  if (isSuccess) successCount.add(1);
  graphqlDuration.add(res.timings.duration);
}
