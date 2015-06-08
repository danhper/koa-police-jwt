'use strict';

var koa          = require('koa');
var koaPolice    = require('koa-police');
var koaPoliceJwt = require('..');

var app = koa();
var db = {
  1: 'user-1'
};

var jwtStrategy = koaPoliceJwt({
  secret: 'i-am-very-secret',
  processDecoded: function *(context, tokenInfo) {
    return db[tokenInfo.userId];
  },
  expireField: 'tokenExpiresAt',
  header: 'authorization',
  query: 'accessToken'
});

app.use(koaPolice({
  defaultStrategies: [jwtStrategy],
  policies: [{path: /\/protected.*/}, {path: '/home', enforce: false}]
}));

app.use(function *() {
  this.body = 'you accessed ' + this.path + ' as ' + this.state.user || 'anonymous';
});

app.listen(5000);
