const passport = require('passport');
const axios = require('axios');
const { OAuth2Strategy } = require('passport-oauth');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const redisClient = require('../utils/redis');
const Promise = require('bluebird');

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
      redisClient.set(`db:${profile._id}`, JSON.stringify(profile)),
      redisClient.set(`token:${req.session.id}`, JSON.stringify(tokens), 'ex', Number(process.env.EKO_ACCESS_TOKEN_EXPIREIN)),
    ])
    .then(() => { 
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
  ignoreExpiration: false,
  passReqToCallback: true
}, (req, payload, done) => {
  done(null, _.omit(payload, 'iat', 'exp'));
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
