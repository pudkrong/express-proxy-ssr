const Redis = require('ioredis');
const redisClient = new Redis({
  keyPrefix: 'eko-app:',
  enableReadyCheck: true,
  lazyConnect: true,
});

redisClient
  .on('error', (err) => {
    console.error('Redis error: ', err);
  });

module.exports = redisClient;
