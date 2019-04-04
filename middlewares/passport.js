const passport = require('passport');
const axios = require('axios');
const { OAuth2Strategy } = require('passport-oauth');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const redisClient = require('../utils/redis');
const Promise = require('bluebird');
const crypto = require('crypto');
const Joi = require('joi');

passport.serializeUser((user, done) => {
  done(null, user._id.toString());
});

passport.deserializeUser((id, done) => {
  redisClient
    .get(`db:${id}`)
    .then(data => {
      const user = JSON.parse(data);
      done(null, user);
    })
    .catch(err => {
      done(err);
    });
});

/**
 * Eko API OAuth.
 */
const oauth2List = process.env.EKO_OAUTH2_LIST.split(',');
oauth2List.forEach((item) => {
  const [name, clientId, clientSecret, host, returnTo] = item.split('|');

  const EkoOAuth2Strategy = new OAuth2Strategy({
    authorizationURL: host + process.env.EKO_AUTHORIZE_URL,
    tokenURL: host + process.env.EKO_TOKEN_URL,
    clientID: clientId,
    clientSecret: clientSecret,
    callbackURL: `/oauth2/${name}/callback`,
    passReqToCallback: true,
    scope: process.env.EKO_SCOPE,
    state: true,
  }, async (req, accessToken, refreshToken, profile, done) => {
    try {
      const tokens = { accessToken, refreshToken };
      const authCode = crypto.randomBytes(24).toString('hex');
      const profileStr = JSON.stringify(profile);

      await redisClient
        .multi()
        // Save user profile into DB
        .set(`db:${profile._id}`, profileStr)
        // Save session id associated to user
        .set(`user:${profile._id}`, req.session.id, 'ex', Math.floor(req.session.cookie.maxAge / 1000))
        // Save authCode
        .set(`authcode:${authCode}:cookie`, req.headers.cookie, 'ex', 60)
        .set(`authcode:${authCode}:user`, profileStr, 'ex', 60)
        .exec();

      req.session.tokens = tokens;
      req.session.returnTo = `${returnTo}?eko-auth-code=${authCode}`;

      done(null, profile);
    } catch (error) {
      done(error);
    }
  });
  EkoOAuth2Strategy.userProfile = (accessToken, done) => {
    axios
    .get(host + process.env.EKO_USER_INFO_URL, { headers: { Authorization: `Bearer ${accessToken}` }})
    .then((data) => { 
      done(null, data.data); 
    })
    .catch((err) => { 
      done(err); 
    });
  };
  passport.use(name, EkoOAuth2Strategy);
});
 
passport.use('jwt', new JwtStrategy({
  secretOrKey: process.env.JWT_SECRET,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  algorithms: ['HS256'],
  ignoreExpiration: true,
  passReqToCallback: true
}, async (req, payload, done) => {  
  try {
    // Double check to user is still valid
    const sessionId = await redisClient.get(`user:${payload._id}`);
    if (!sessionId) throw new Error('User session id is not found');

    const session = await Promise.promisify(req.sessionStore.get, { context: req.sessionStore })(sessionId);
    if (!session) throw new Error('User session data is not found');

    return done(null, _.omit(payload, 'iat', 'exp'));
  } catch (err) {
    console.error(`JWT authentication error`, err);
    return done(null, false);
  }
}));

/**
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

/**
 * Authorization Required middleware.
 */
exports.isAuthorized = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/oauth2/eko');
};

exports.logout = async (req, res, next) => {
  try {
    const schema = Joi.object().keys({
      expire: Joi.date().timestamp('unix'),
      request: Joi.string().trim(),
    }).requiredKeys('expire', 'request');

    const { expire, request } = Joi.attempt(req.body, schema);
   
    req.sessionStore.destroy(req.session.id);
    next();
  } catch (err) {
    next(err);
  }
};
