'use strict';

const assert              = require('assert');
const AuthenticationError = require('koa-police').AuthenticationError;
const jwt                 = require('jwt-simple');

const decodeToken = function (token, secret, expireField) {
  try {
    let decoded = jwt.decode(token, secret);
    if (expireField && Date.parse(decoded[expireField]) <=  Date.now()) {
      throw new AuthenticationError('token expired');
    }
    return decoded;
  } catch (err) {
    throw new AuthenticationError('could not decode token');
  }
};

const parseHeader = function (authHeader) {
  let parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    throw new AuthenticationError('bad authentication header');
  }
  return parts[1];
};

module.exports = function (options) {
  assert(typeof options.secret === 'function' || typeof options.secret === 'string',
    'secret must be a string or a function');

  if (!options.header && !options.query && !options.getToken) {
    options.header = 'authorization';
  }

  const isScopeAllowed = function (scope) {
    if (!options.allowedScopes) {
      return true;
    }
    for (let allowedScope of options.allowedScopes) {
      if (scope === allowedScope) {
        return true;
      }
    }
    return false;
  };

  const authenticateToken = function *(token, context) {
    let secret = options.secret;
    if (typeof secret === 'function') {
      secret = yield secret(context);
    }
    if (options.isRevoked) {
      let revoked = yield options.isRevoked(token, context);
      if (revoked) {
        throw new AuthenticationError('token has been revoked');
      }
    }
    return decodeToken(token, secret, options.expireField);
  };

  const findToken = function *(request) {
    let token;
    if (options.getToken) {
      return options.getToken(request);
    }
    if (options.header && request.header[options.header]) {
      return parseHeader(request.header[options.header]);
    }
    if (!token && options.query) {
      token = request.query[options.query];
    }
    return token;
  };

  return {
    name: 'jwt',
    authenticate: function *(context, scope) {
      let token = yield findToken(context.request);
      if (!token || !isScopeAllowed(scope)) {
        return false;
      }
      let tokenInfo = yield authenticateToken(token, context);
      if (!tokenInfo) {
        return false;
      }
      if (options.processDecoded) {
        tokenInfo = yield options.processDecoded(context, tokenInfo);
      }
      return tokenInfo;
    }
  };
};
