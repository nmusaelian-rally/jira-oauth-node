require('dotenv').config()
const fs = require('fs');
const OAuth = require('oauth').OAuth;
const express = require('express');
const session = require('express-session');
const config = require('./config');

const privateKeyData = fs.readFileSync(config["consumerPrivateKeyFile"], "utf8");
const consumerKey = config["consumerKey"]
const signatureMethod = "RSA-SHA1"
const oauthVersion = "1.0"

const oauthUrl = `${config.jiraUrl}/plugins/servlet/oauth/`;
const protectedResource = `${config.jiraUrl}/rest/api/2/project`
const port = process.env.PORT || 3000;
const callbackUrl = `http://localhost:${port}/callback`

// monkey-patch OAuth.get: 
// In oauth library code, OAuth.get calls _performSecureRequest with next-to-last argument null ,
// which results is content-type defaulting to "application/x-www-form-urlencoded",
// Jira requires "application/json" hence it is explicitly passed
 
OAuth.prototype.get = function (url, oauth_token, oauth_token_secret, callback, post_content_type) {
  return this._performSecureRequest(oauth_token, oauth_token_secret, "GET", url, null, "", post_content_type, callback);
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


const app = module.exports = express();
app.use(session({
  secret: 'ssshhhh!',
  resave: false,
  saveUninitialized: true,
  cookie: {secure: false}
}));
app.use((req, res, next) => {
  res.session = req.session;
  next();
});

app.get('/', (request, response) => response.send('ok'));
app.get('/connect', (request, response) => {
  consumer.getOAuthRequestToken((error, oauthToken, oauthTokenSecret) => {
      if (error) {
        response.send('Error getting Request token');
      }
      else {
        request.session.oauthRequestToken = oauthToken;
        request.session.oauthRequestTokenSecret = oauthTokenSecret;
        response.redirect(`${oauthUrl}authorize?oauth_token=${request.session.oauthRequestToken}`);
      }
    }
  );
});

app.get('/callback', (request, response) => {
  consumer.getOAuthAccessToken(
    request.session.oauthRequestToken,
    request.session.oauthRequestTokenSecret,
    request.query.oauth_verifier,
    (error, oauthAccessToken, oauthAccessTokenSecret) => {
      if (error) {
        response.send("error getting Access token");
      }
      else {
        console.log('CONSUMER KEY: ', consumerKey)
        console.log('TOKEN:', oauthAccessToken)
        console.log('SIGNATURE METHOD: ', signatureMethod, ', OAUTH VERSION: ', oauthVersion)
        console.log('PRIVATE KEY:\n', privateKeyData)

        request.session.oauthAccessToken = oauthAccessToken;
        request.session.oauthAccessTokenSecret = oauthAccessTokenSecret;
        consumer.get(protectedResource,
        request.session.oauthAccessToken,
          request.session.oauthAccessTokenSecret,
          function (error, data) {
            if (error) throw error;
            data = JSON.parse(data);
            console.log(`${protectedResource} returned ${data.length} items.`)
            response.send(`Projects: ${data.map(proj => 
              '<li>key: ' + proj['key'] + ', name:' + proj['name'] + ', id:' + proj['id'] + '<\li>').join('')}`);
          },
          "application/json"
        );
      }
    }
  );
});


app.listen(port);