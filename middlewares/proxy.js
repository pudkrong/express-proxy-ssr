const proxy = require('express-http-proxy');
const url = require('url');
const redisClient = require('../utils/redis');
const jwt = require('jsonwebtoken');
const cheerio = require('cheerio');

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
  }, { rules: [], default: null });

  function getHost(req) {  
    return req.selectedHost;
  }

  return proxy(getHost, {
    timeout: 20000,
    limit: '10mb',
    preserveHostHdr: false,
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
      const selectedRule = rulesMap.rules.filter(rule => {
        return rule.pathRegex.test(req.path);
      });
      if (selectedRule.length) {
        req.selectedHost = selectedRule[0].host;
        req.rewritePath = selectedRule[0].path;
        return true;
      } else {
        req.selectedHost = rulesMap.default;
        return rulesMap.default ? !req.path.match(/^\/(oauth2|api|user|public)/, 'i') : false;
      }
    },
    proxyReqPathResolver: (req) => {
      if (req.rewritePath) {
        const replaceRegex = new RegExp(`^\/${req.rewritePath}\/|^\/${req.rewritePath}$`, 'i');

        return req.path.replace(replaceRegex, '/');
      } else {
        return req.path;
      }
    },
    userResDecorator: (proxyRes, proxyResData, userReq, userRes) => {
      if (/\.(js|css|jpe?g|gif|png|svg|ttf)$/i.test(userReq.path)) {
        return proxyResData;
      } else {
        // Rewrite path
        const pathPrefix = userReq.rewritePath;
        if (!pathPrefix) {
          return proxyResData;
        } else {
          const $ = cheerio.load(proxyResData.toString('utf-8'));
          $('[src]').each((i, el) => {
            const orig = $(el).attr('src');
            if (!/^http/.test(orig)) $(el).attr('src', `/${pathPrefix}${orig}`);
          });

          $('[href]').each((i, el) => {
            const orig = $(el).attr('href');
            if (!/^http/.test(orig)) $(el).attr('href', `/${pathPrefix}${orig}`);
          }); 

          return $.html();         
        }
      }
    }
  });
}

