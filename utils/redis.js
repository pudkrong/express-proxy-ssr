const Redis = require('ioredis');
const redisClient = new Redis({
  keyPrefix: 'eko-app:',
});

module.exports = redisClient;
