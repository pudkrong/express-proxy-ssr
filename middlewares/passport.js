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
const EkoOAuth2Strategy = new OAuth2Strategy({
  authorizationURL: process.env.EKO_AUTHORIZE_URL,
  tokenURL: process.env.EKO_TOKEN_URL,
  clientID: process.env.EKO_CLIENT_ID,
  clientSecret: process.env.EKO_SECRET,
  callbackURL: process.env.EKO_CALLBACK_URL,
  passReqToCallback: true,
  scope: process.env.EKO_SCOPE,
  state: true,
}, (req, accessToken, refreshToken, profile, done) => {
  const tokens = { accessToken, refreshToken };
  Promise.all([
      // Save user profile into DB
      redisClient.set(`db:${profile._id}`, JSON.stringify(profile)),
      // Save session id associated to user
      redisClient.set(`user:${profile._id}`, req.session.id, 'ex', Math.floor(req.session.cookie.maxAge / 1000)),
    ])
    .then(() => {    
      req.session.tokens = tokens;   
      done(null, profile); 
    })
    .catch(done);
});
EkoOAuth2Strategy.userProfile = (accessToken, done) => {
  axios
  .get(process.env.EKO_USER_INFO_URL, { headers: { Authorization: `Bearer ${accessToken}` }})
  .then((data) => { 
    done(null, data.data); 
  })
  .catch((err) => { 
    done(err); 
  });
};
passport.use('eko', EkoOAuth2Strategy);
 
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
