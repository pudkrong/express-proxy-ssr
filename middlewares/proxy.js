const proxy = require('express-http-proxy');
const url = require('url');
const redisClient = require('../utils/redis');
const jwt = require('jsonwebtoken');

module.exports = (host) => {
  return proxy(host, {
    timeout: 2000,
    limit: '10mb',
    preserveHostHdr: true,
    parseReqBody: false,
    proxyReqOptDecorator: async (proxyReqOpts, srcReq) => { 
      const user = srcReq.user;
      if (user) {      
        const ttl = await redisClient.ttl(`token:${srcReq.session.id}`);
        proxyReqOpts.headers['x-eko-user'] = jwt.sign(user, process.env.JWT_SECRET, {
          algorithm: process.env.JWT_ALGORITHM,
          expiresIn: `${ttl}s`
        });
      } 

      return proxyReqOpts;
    }, 
  });
}

