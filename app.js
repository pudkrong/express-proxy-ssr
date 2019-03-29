/**
 * Module dependencies.
 */
const dotenv = require('dotenv');
/**
 * Load environment variables from .env file, where API keys and passwords are configured.
 */
dotenv.config({ path: '.env.example' });

const express = require('express');
const compression = require('compression');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redisClient = require('./utils/redis');
const bodyParser = require('body-parser');
const logger = require('morgan');
const chalk = require('chalk');
const errorHandler = require('errorhandler');
const lusca = require('lusca');
const flash = require('express-flash');
const path = require('path');
const passport = require('passport');
const expressStatusMonitor = require('express-status-monitor');
const multer = require('multer');

const upload = multer({ dest: path.join(__dirname, 'uploads') });

/**
 * Controllers (route handlers).
 */

/**
 * API keys and Passport configuration.
 */
const passportMiddleware = require('./middlewares/passport');

/**
 * Create Express server.
 */
const app = express();

/**
 * Connect to MongoDB.
 */
// mongoose.set('useFindAndModify', false);
// mongoose.set('useCreateIndex', true);
// mongoose.set('useNewUrlParser', true);
// mongoose.connect(process.env.MONGODB_URI);
// mongoose.connection.on('error', (err) => {
//   console.error(err);
//   console.log('%s MongoDB connection error. Please make sure MongoDB is running.', chalk.red('✗'));
//   process.exit();
// });

/**
 * Express configuration.
 */
const ignoreSession = /^\/(?!api\/).*/;

app.set('host', '0.0.0.0');
app.set('port', process.env.PORT || 8080);
app.use(expressStatusMonitor());
app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  store: new RedisStore({ client: redisClient }),
  resave: true,
  saveUninitialized: false,
  secret: process.env.SESSION_SECRET || 'my secret',
  cookie: { maxAge: Number(process.env.SESSION_MAXAGE) }, // two weeks in milliseconds
}));
app.use(passport.initialize());
app.use(passport.session());

// Rate limit
require('./middlewares/ratelimit')(app);

// Save return to
// app.use((req, res, next) => {
//   if (req.session && !req.user && !req.path.match(/^\/oauth2/)) {
//     req.session.returnTo = req.originalUrl;
//   }
//   next();
// });

// Proxy to SSR
app.use(require('./middlewares/proxy')(process.env.PROXY_RULES));

app.use(flash());
app.use(lusca.xframe('SAMEORIGIN'));
app.use(lusca.xssProtection(true));
app.disable('x-powered-by');

// Eko OAuth2
const oauth2List = process.env.EKO_OAUTH2_LIST.split(',');
oauth2List.forEach((item) => {
  const [name] = item.split('|');
  app.get(`/oauth2/${name}`, passport.authenticate(name));  
  app.get(`/oauth2/${name}/callback`, passport.authenticate(name, { failureRedirect: '/error' }), (req, res) => {
    res.redirect(req.session.returnTo ? req.session.returnTo : '/user');
  });  
});
app.post('/oauth2/slo', passportMiddleware.logout, (req, res) => {
  res.end('Waiting for implement');
});

// Eko APIs
const testController = require('./controllers/test');
app.all('/api/*', passport.authenticate('jwt', { session: false }), testController.test);

app.get('/public', (req, res) => {
  res.end('public');
});
app.get('/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.end(`Login as ${req.user.firstname}`);
  } else {
    res.end(`You are not login yet`);
  }
});

/**
 * Error Handler.
 */
if (process.env.NODE_ENV === 'development') {
  // only use in development
  app.use(errorHandler());
} else {
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).send('Server Error');
  });
}

/**
 * Start Express server.
 */
redisClient
  .connect()
  .then(() => {
    app.listen(app.get('port'), () => {
      console.log('%s App is running at http://localhost:%d in %s mode', chalk.green('✓'), app.get('port'), app.get('env'));
      console.log('  Press CTRL-C to stop\n');
    });
  });

module.exports = app;
