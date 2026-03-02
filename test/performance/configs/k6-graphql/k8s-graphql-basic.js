// k6 GraphQL Basic Performance Test (no auth)
// Usage: k6 run k8s-graphql-basic.js
import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const graphqlDuration = new Trend('graphql_duration', true);
const successCount = new Counter('success_count');

export const options = {
  stages: [
    { duration: '30s', target: 50 },   // ramp up
    { duration: '2m', target: 50 },    // steady state
    { duration: '30s', target: 0 },    // ramp down
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
  '{ item(id: "2") { id name price } }',
  '{ items { id name description price quantity category } }',
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

  const success = check(res, {
    'status is 200': (r) => r.status === 200,
    'has data': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data !== undefined;
      } catch (e) {
        return false;
      }
    },
  });

  errorRate.add(!success);
  if (success) successCount.add(1);
  graphqlDuration.add(res.timings.duration);
}
