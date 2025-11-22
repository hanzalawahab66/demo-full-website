const jwt = require('jsonwebtoken');

const secret = 'dev-secret-change-me';
const payload = {
  userId: 1001,
  email: 'admin@example.com',
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
};

const token = jwt.sign(payload, secret);
console.log(token);
console.error('Generated admin token for testing endpoints.');