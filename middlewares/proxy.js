const proxy = require('express-http-proxy');
const url = require('url');
const redisClient = require('../utils/redis');
const jwt = require('jsonwebtoken');
const _ = require('lodash');

module.exports = (rules, options) => {
  options = _.defaultsDeep(options, {
    preserveRoutes: '^\/(oauth2|api|user)',
    proxy: {
      timeout: 10000,
      limit: '10mb',
      getHost: getHost,
      filter: filter,
      rewritePath: rewritePath,
      proxyReq: proxyReq,
      modifyResHeaders: modifyResHeaders,
    }
  });

  const preserveRoutesRegex = new RegExp(options.preserveRoutes);
  const rulesMap = rules.split(',').reduce((acc, rule) => {
    const data = rule.split('=');
    const path = data[0].toLowerCase().trim();
    const host = data[1].toLowerCase().trim();

    if (path == '*') {
      acc.default = host;
    } else {
      const isHost = /^[\w\.]+(\:\d+)?$/.test(path);
      const pathRegex = isHost ? new RegExp(`${path.replace(/\./g, '\.')}`) : new RegExp(path);
      acc.rules.push({
        isHost,
        path,
        pathRegex,
        host,
      });
    }

    return acc;
  }, { rules: [], default: null });

  function getHost (req) {  
    return req.selectedHost;
  }

  function filter (req, res) {
    const selectedRule = rulesMap.rules.find((rule) => {
      return rule.isHost ? 
        rule.pathRegex.test(req.headers.host || '') : 
        rule.pathRegex.test(req.url);
    });

    if (selectedRule) {
      req.selectedHost = selectedRule.host;
      if (selectedRule.isHost) {
        req.target = selectedRule.path;
        req.rewritePath = req.url;
      } else {
        const matches = selectedRule.pathRegex.exec(req.url);
        const newPath = req.url.replace(matches[0], '');
        req.rewritePath = (newPath[0] == '/') ? newPath : `/${newPath}`;
      }

      return true;
    } else {
      req.selectedHost = rulesMap.default;
      req.rewritePath = req.url;

      return req.selectedHost ? !preserveRoutesRegex.test(req.path) : false;
    }
  }

  function rewritePath (req) {
    return req.rewritePath;
  }

  async function proxyReq (proxyReqOpts, srcReq) {
    let user;
    if (srcReq.user) {
      user = srcReq.user;
    } else if (srcReq.query['eko-auth-code']) {
      const authCode = srcReq.query['eko-auth-code'];
      const userData = await redisClient.get(`authcode:${authCode}:user`);
      if (userData) user = JSON.parse(userData);
    }

    if (user) {      
      proxyReqOpts.headers['x-eko-user'] = jwt.sign(user, process.env.JWT_SECRET, {
        algorithm: process.env.JWT_ALGORITHM,
      });
    }

    delete  proxyReqOpts.headers.cookie;

    return proxyReqOpts;
  }

  async function modifyResHeaders (headers, userReq, userRes, proxyReq, proxyRes) {
    const authCode = userReq.query['eko-auth-code'];
    if (authCode) {
      const cookie = await redisClient.get(`authcode:${authCode}:cookie`);
      headers['set-cookie'] = cookie;
    }

    if (userReq.target) {
      headers['host'] = userReq.target;
    }

    return headers;
  }

  return proxy(options.proxy.getHost, {
    timeout: options.proxy.timeout,
    limit: options.proxy.limit,
    preserveHostHdr: false,
    parseReqBody: false,
    memoizeHost: false,
    proxyReqOptDecorator: options.proxy.proxyReq,
    filter: options.proxy.filter,
    proxyReqPathResolver: options.proxy.rewritePath,
    userResHeaderDecorator: options.proxy.modifyResHeaders,
  });
}

