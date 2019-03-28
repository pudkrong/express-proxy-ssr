const proxy = require('express-http-proxy');
const url = require('url');
const redisClient = require('../utils/redis');
const jwt = require('jsonwebtoken');

module.exports = (rules) => {
  const rulesMap = rules.split(',').reduce((acc, rule) => {
    const data = rule.split('=');
    const path = data[0].toLowerCase().trim().replace(/\//, '');
    const host = data[1].toLowerCase().trim();

    if (path == '*') {
      acc.default = host;
    } else {
      acc.rules.push({
        path: path,
        pathRegex: new RegExp(`^\/${path}\/|^\/${path}$`, 'i'),
        host: host,
      });
    }

    return acc;
  }, { rules: [], default: {} });

  function getHost(req) {  
    const selectedRule = rulesMap.rules.filter(rule => {
      return rule.pathRegex.test(req.path);
    });

    if (selectedRule.length) {
      req.proxyRule = selectedRule[0].path;
      return selectedRule[0].host;
    } else {
      return rulesMap.default;
    }
  }

  return proxy(getHost, {
    timeout: 2000,
    limit: '10mb',
    preserveHostHdr: true,
    parseReqBody: false,
    memoizeHost: false,
    proxyReqOptDecorator: async (proxyReqOpts, srcReq) => { 
      const user = srcReq.user;
      if (user) {      
        proxyReqOpts.headers['x-eko-user'] = jwt.sign(user, process.env.JWT_SECRET, {
          algorithm: process.env.JWT_ALGORITHM,
        });
      }

      return proxyReqOpts;
    },
    filter: (req, res) => {
      const shouldProxy = !req.path.match(/^\/(oauth2|api|user|public)/, 'i');
      return shouldProxy;
    },
    proxyReqPathResolver: (req) => {
      if (req.proxyRule) {
        const replaceRegex = new RegExp(`^\/${req.proxyRule}\/|^\/${req.proxyRule}$`, 'i');

        delete req.proxyRule;
        return req.path.replace(replaceRegex, '/');
      } else {
        return req.path;
      }
    }
  });
}

