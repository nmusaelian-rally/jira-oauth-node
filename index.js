/* eslint-disable @typescript-eslint/camelcase */
/* eslint-disable @typescript-eslint/no-var-requires */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const fs = require('fs');
const OAuth = require('oauth').OAuth;
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const config = require('./config');

const privateKeyData = fs.readFileSync(
  config['consumerPrivateKeyFile'],
  'utf8'
);
const consumerKey = config['consumerKey'];
const signatureMethod = 'RSA-SHA1';
const oauthVersion = '1.0';

const oauthUrl = `${config.jiraUrl}/plugins/servlet/oauth/`;
//const protectedResource = `${config.jiraUrl}/rest/api/2/project`;
const port = 9999;
//const callbackUrl = `http://localhost:${port}/callback`;
const callbackUrl = `http://tenfoot-build-01.f4tech.com:${port}/callback`;
const sessionSecret = `secret ${Math.random()}`;
const sessionCookieExpireDate = new Date(
  new Date().setFullYear(new Date().getFullYear() + 1)
);

// monkey-patch OAuth.get:
// In oauth library code, OAuth.get calls _performSecureRequest with next-to-last argument null ,
// which results is content-type defaulting to "application/x-www-form-urlencoded",
// Jira requires "application/json" hence it is explicitly passed

OAuth.prototype.get = function (
  url,
  oauth_token,
  oauth_token_secret,
  callback,
  post_content_type
) {
  return this._performSecureRequest(
    oauth_token,
    oauth_token_secret,
    'GET',
    url,
    null,
    '',
    post_content_type,
    callback
  );
};
// end monkey-patch

const consumer = new OAuth(
  `${oauthUrl}request-token`,
  `${oauthUrl}access-token`,
  consumerKey,
  privateKeyData,
  oauthVersion,
  callbackUrl,
  signatureMethod
);

const app = express();
app.set('port', port);
app.use(helmet());
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false, //don't save empty sessions
    cookie: {
      secure: false, //not limited to https for now
      httpOnly: true, //cookie is sent only over HTTP(S), not client js, helps protect against XSS
      expires: sessionCookieExpireDate,
    },
  })
);
app.use((req, res, next) => {
  res.session = req.session;
  next();
});

app.get('/', (request, response) => response.send('ok'));
app.get('/connect', (request, response) => {
  consumer.getOAuthRequestToken((error, oauthToken, oauthTokenSecret) => {
    if (error) {
      response.send(`Error getting Request token. ${error}`);
    } else {
      request.session.oauthRequestToken = oauthToken;
      request.session.oauthRequestTokenSecret = oauthTokenSecret;
      response.redirect(
        `${oauthUrl}authorize?oauth_token=${request.session.oauthRequestToken}`
      );
    }
  });
});

app.get('/callback', (request, response) => {
  consumer.getOAuthAccessToken(
    request.session.oauthRequestToken,
    request.session.oauthRequestTokenSecret,
    request.query.oauth_verifier,
    (error, oauthAccessToken) => {
      if (error) {
        response.send(`Error getting Access token. ${error}`);
      } else {
        response.send(`OAUTH TOKEN: ${oauthAccessToken}`);
      }
    }
  );
});

app.listen(port);
