# koa-police-jwt

[![npm version](https://badge.fury.io/js/koa-police-jwt.svg?time=20150608163600)](http://badge.fury.io/js/koa-police-jwt)
[![Build Status](https://travis-ci.org/tuvistavie/koa-police-jwt.svg)](https://travis-ci.org/tuvistavie/koa-police-jwt) [![Coverage Status](https://coveralls.io/repos/tuvistavie/koa-police-jwt/badge.svg?time=20150608163600)](https://coveralls.io/r/tuvistavie/koa-police-jwt)

A [koa-police](https://github.com/tuvistavie/koa-police) strategy to login users with [JSON Web Token](http://jwt.io/).

## Installation

Simply run

```sh
$ npm install --save koa-police-jwt
```

## Usage

This module exports a function that take a the JWT secret and returns a `koa-police` strategy.
You can call it like this.

```javascript
var koaPoliceJwt = require('koa-police-jwt');
var jwtStrategy = koaPoliceJwt({secret: 'my-secret'});
```

You then only need to add this strategy to the `defaultStrategies` array when
initializing `koa-police`.
A full example is provided in [the example directory](./example).

### Customization

#### Getting the token

By default, `koa-police-jwt` will look for the `Authorization` header with the form `Bearer [token]`. However, you can customize the way you want to look
for the token.
If you want to use another header, you can pass `header: 'x-my-header'` in the
initialization options. This will use `x-my-header` instead of `authorization`.
If you want to use a query parameter, you can pass `query: 'myQueryParam'`, this will look in the query parameters for the token.
Both options can be used together.

If you need more flexibility to get the token, you can pass a function to `getToken`, which will be passed the request as parameter, for example.

```javascript
var jwtStrategy = koaPoliceJwt({
  secret: 'my-secret',
  getToken: function (request) {
    return request.body.myToken;
  }});
```

#### Using a dynamic secret

If you need to use a dynamic secret, you can pass a generator function  instead of a string.

```javascript
var jwtStrategy = koaPoliceJwt({
  secret: function *(context) {
    var mySecret = yield getMySecretFromWhereverIWant(context);
    return mySecret;
  }
});
```

#### Post processing decoded data

If you want to process the decoded data, you can pass a generator function to the `processDecoded` option. For example:

```javascript
var jwtStrategy = koaPoliceJwt({
  secret: 'my-secret',
  processDecoded: function *(context, decoded) {
    return yield context.db.findUser(decoded.userId);
  }
});
```

The returned result will be replace by whatever you return in this function.

#### Limiting allowed scopes

By default, the `jwtStrategy` will not care which scope you are using,
however, you can restrict the scopes you want to use by passing an array to the `allowedScopes` option.

```javascript
var jwtStrategy = koaPoliceJwt({
  secret: 'my-secret',
  allowedScopes: ['user']
});
```

So if you have koa-police initialized in the following way

```
app.use(koaPolice({
  defaultStrategies: [jwtStrategy],
  policies: [{path: /\/admin.*/, scope: 'admin'}, {path: /.*/, scope: 'user'}]
}));
```

`jwtStrategy` will always fail for the `admin` scope.
