const redisClient = require('../utils/redis');

module.exports = (app) => {
  const limiter = require('express-limiter')(app, redisClient);

  limiter({
    path: '*',
    method: 'all',
    lookup: ['connection.remoteAddress'],
    total: 500,
    expire: 1000 * 60,
  });

  limiter({
    path: '/api',
    method: 'all',
    lookup: (req, res, options, next) => {
      if (req.user) {
        options.lookup = ['user._id'];
      } else {
        options.lookup = ['connection.remoteAddress'];
      }

      next();
    },
    total: 500,
    expire: 1000 * 60,
  });
}

