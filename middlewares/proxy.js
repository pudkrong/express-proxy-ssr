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
        proxyReqOpts.headers['x-eko-user'] = jwt.sign(user, process.env.JWT_SECRET, {
          algorithm: process.env.JWT_ALGORITHM,
        });
      }

      proxyReqOpts.headers['host'] = process.env.PROXY_TO;
      return proxyReqOpts;
    },
    filter: (req, res) => {
      const shouldProxy = !req.path.match(/^\/(oauth2|api|test|public)/, 'i');
      return shouldProxy;
    },
    proxyReqPathResolver: (req) => {
      return `/${req.method.toLowerCase()}`;
    } 
  });
}

