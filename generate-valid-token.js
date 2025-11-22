const jwt = require('jsonwebtoken');

// Use the same secret as the backend
const JWT_SECRET = 'dev-secret-change-me';

// Create a payload for our test seller
const payload = {
    userId: 9999999999999,
    email: 'testseller@example.com',
    role: 'seller',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
};

// Generate the token
const token = jwt.sign(payload, JWT_SECRET);

console.log('Generated JWT Token:');
console.log(token);
console.log('\nPayload:');
console.log(JSON.stringify(payload, null, 2));
console.log('\nYou can copy this token and use it for testing.');