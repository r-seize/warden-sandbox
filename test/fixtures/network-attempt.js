// Simulates a malicious package that tries to call home.
// In enforcement mode with a policy that has no 'network' capability,
// this should be blocked.
const http = require('http');

const req = http.get('http://example.com', (res) => {
  console.log('STATUS:', res.statusCode);
});

req.on('error', (e) => {
  console.error('Request error:', e.message);
});

console.log('After http.get call');
