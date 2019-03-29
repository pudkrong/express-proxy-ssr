const Redis = require('ioredis');

let redisClient;
if (/true/i.test(process.env.REDIS_CLUSTER)) {
  console.log('Using redis cluster');

  const nodes = process.env.REDIS_CLUSTER_LIST.split(',').map((node) => {
    const [host, port] = node.split(':');
    return { host, port: Number(port) };
  });
  redisClient = new Redis.Cluster(nodes, {
    enableReadyCheck: true,
    scaleReads: 'slave',
    lazyConnect: true,
    keyPrefix: 'eko-app:',      
  });
} else {
  console.log('Using redis standalone');

  redisClient = new Redis({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    keyPrefix: 'eko-app:',
    enableReadyCheck: true,
    lazyConnect: true,
  });
}

redisClient
  .on('error', (err) => {
    console.error('Redis error: ', err);
  })
  .on('close', () => { console.log('Redis is closed'); })
  .on('reconnecting', () => { console.log('Redis is reconnecting'); })
  .on('ready', () => { console.log('Redis is ready'); })
  .on('connect', () => { console.log('Redis is connected'); });

module.exports = redisClient;
