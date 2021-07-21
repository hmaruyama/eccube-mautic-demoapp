'use strict';

require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const fs = require("fs");
const clientOAuth2 = require('client-oauth2');
const request = require('request');
const GraphQLClient = require('graphql-request').GraphQLClient;
const sleep = require('sleep');
const app = express();
const PORT = process.env.PORT || 3000;
const EC_SECRET = process.env.HM_EC_WEBHOOK_SECRET;
const MT_SECRET = process.env.HM_MT_WEBHOOK_SECRET;
const ecEndpoint = process.env.HM_EC_ENDPOINT;
const mtEndpoint = process.env.HM_MT_ENDPOINT;
const ecRedirectUri = app.get('env') == 'development' ? "http://localhost:" + PORT + "/auth/ec/callback" : process.env.HM_HEROKU_APP_URL + '/auth/ec/callback';
const mtRedirectUri = app.get('env') == 'development' ? "http://localhost:" + PORT + '/auth/mt/callback' : process.env.HM_HEROKU_APP_URL + '/auth/mt/callback';

const ecAuth = new clientOAuth2({
  clientId: process.env.HM_EC_CLIENTID,
  clientSecret: process.env.HM_EC_CLIENTSECRET,
  accessTokenUri: process.env.HM_EC_TOKEN_URL,
  authorizationUri: process.env.HM_EC_AUTH_URL,
  redirectUri: ecRedirectUri,
  scopes: 'read',
  state: 'abcd'
});

const mtAuth = new clientOAuth2({
  clientId: process.env.HM_MT_CLIENTID,
  clientSecret: process.env.HM_MT_CLIENTSECRET,
  accessTokenUri: process.env.HM_MT_TOKEN_URL,
  authorizationUri: process.env.HM_MT_AUTH_URL,
  redirectUri: mtRedirectUri,
  scopes: '',
  state: 'abcd'
});

// save raw body
app.use ((req, res, next) => {
  let data = '';
  req.setEncoding('utf8');

  req.on('data', chunk => data += chunk);
  req.on('end', () => {
    req.body = data;
    return next();
  });
});

app.get('/', function (req, res) {
  res.send();
});

app.get('/auth/ec', function (req, res) {

  // https://github.com/mulesoft-labs/js-client-oauth2

  var uri = ecAuth.code.getUri();
  res.redirect(uri)
});

app.get('/auth/ec/callback', function (req, res) {
  ecAuth.code.getToken(req.originalUrl)
    .then(function (user) {
      console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }

      // We should store the token into a database.
      fs.writeFile('ecToken.txt', user.accessToken, (err, data) => {
        if(err) console.log(err);
        else console.log('write end');
      });
      return res.send(user.accessToken);
    })
})

app.get('/auth/mt', function (req, res) {

  // https://github.com/mulesoft-labs/js-client-oauth2

  var uri = mtAuth.code.getUri();
  res.redirect(uri)
});

app.get('/auth/mt/callback', function (req, res) {
  mtAuth.code.getToken(req.originalUrl)
    .then(function (user) {
      console.log(user) //=> { accessToken: '...', tokenType: 'bearer', ... }

      // We should store the token into a database.
      fs.writeFile('mtToken.txt', user.accessToken, (err, data) => {
        if(err) console.log(err);
        else console.log('write end');
      });
      return res.send(user.accessToken);
    })
})

app.post('/webhook/ec', (req, res) => {

  // 開発環境なら署名検証をスキップする
  if (app.get('env') != 'development') {
    // optional signature verification
    const receivedSignature = req.headers['x-eccube-signature'];
    console.log('headers:', req.headers);
    console.log('body:', req.body);
    console.log('Received signature (in header):', receivedSignature);

    const computedSignature = crypto.createHmac('sha256', EC_SECRET).update(req.body).digest('hex');
    console.log('Computed signature (from body):', computedSignature);

    if (receivedSignature === computedSignature) {
      console.log('Webhook authenticity verification OK');
    } else {
      console.log('Webhook not authentic!');
    }
  }

  // EC-CUBE APIコール

  const ecToken = fs.readFileSync("ecToken.txt");
  const customerId = JSON.parse(req.body)[0].id;
  let options = { headers: {
    authorization: 'Bearer ' + ecToken,
  }};
  const client = new GraphQLClient(ecEndpoint, options);
  const query = `{
    customer(id:${customerId}) {
        id,
        name01,
        name02,
        email,
        company_name,
        phone_number
    }
  }`;
  
  // 更新後のデータが取得できるように少し遅延させる
  sleep.sleep(5);

  client.request(query, {})
    .then(data => {
      console.log(JSON.stringify(data, null, 2));

      // Mautic APIコール
      let mtToken = fs.readFileSync("mtToken.txt");
      const mtBody = {
        eccubecustomerid: data.customer.id,
        lastname: data.customer.name01,
        firstname: data.customer.name02,
        email: data.customer.email,
        company: data.customer.company_name,
        phone: data.customer.phone_number,
      };
      const options = {
        method: 'POST',
        url: mtEndpoint,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + mtToken,
        },
        body: mtBody,
        json: true
      };
      request(options, function(error, response, body) {
        console.log(JSON.stringify(body));
        res.send("success");
      });

    })
    .catch(error => console.error(error));
}); 

app.post('/mt-webhook', (req, res) => {

  // 開発環境なら署名検証をスキップする
  if (app.get('env') != 'development') {
    // https://github.com/mautic/developer-documentation/blob/master/source/includes/_webhooks.md
    // optional signature verification
    const receivedSignature = req.headers['webhook-signature'];
    console.log('headers:', req.headers);
    console.log('Received signature (in header):', receivedSignature);

    const computedSignature = crypto.createHmac('sha256', MT_SECRET).update(req.body).digest('base64');
    console.log('Computed signature (from body):', computedSignature);

    if (receivedSignature === computedSignature) {
      console.log('Webhook authenticity verification OK');
    } else {
      console.log('Webhook not authentic!');
    }
  }

  // TODO: process body
  const body = JSON.parse(req.body);

  res.send();
});

app.listen(PORT, () => console.log(`App listening on port ${PORT}!`));
