'use strict';

const chai           = require('chai');
const chaiAsPromised = require('chai-as-promised');
chai.use(chaiAsPromised);

const jwt    = require('jwt-simple');
const expect = chai.expect;
const co     = require('co');

const koaPoliceJwt = require('..');

const secret = 'so-secret';
const validToken = jwt.encode({iss: 'myself'}, secret);

let strategy;

const withAuthorization = function (token) {
  beforeEach(function () {
    this.ctx.request.header.authorization = 'Bearer ' + token;
  });
};

describe('koa-police-jwt', function () {
  beforeEach(function () {
    strategy = koaPoliceJwt({
      secret: secret
    });
  });
  beforeEach(function () {
    this.ctx = {request: {header: {}}};
  });

  describe('allowedScopes', function () {
    beforeEach(function () {
      strategy = koaPoliceJwt({
        secret: secret,
        allowedScopes: ['user']
      });
    });
    withAuthorization(validToken);
    context('with not allowed scope', function () {
      it('should return false', function () {
        return expect(co(strategy.authenticate(this.ctx, 'adimn'))).to.eventually.be.false;
      });
    });
    context('with allowed scope', function () {
      it('should return decoded info', function () {
        let promise = co(strategy.authenticate(this.ctx, 'user'));
        return expect(promise).to.eventually.have.property('iss', 'myself');
      });
    });
  });

  context('without token', function () {
    it('should return false', function () {
      return expect(co(strategy.authenticate(this.ctx, 'whatever'))).to.eventually.be.false;
    });
  });

  context('with bad header', function () {
    it('should throw', function () {
      this.ctx.request.header.authorization = 'not really appropriate header';
      return expect(co(strategy.authenticate(this.ctx, 'whatever'))).to.be.rejected;
    });
  });

  context('with bad token', function () {
    withAuthorization('bad-token');
    it('should throw', function () {
      return expect(co(strategy.authenticate(this.ctx, 'whatever'))).to.be.rejected;
    });
  });

  context('with expired token', function () {
    var token = jwt.encode({exp: new Date()}, secret);
    withAuthorization(token);
    it('should throw', function () {
      return expect(co(strategy.authenticate(this.ctx, 'whatever'))).to.be.rejected;
    });
  });

  context('with correct token', function () {
    withAuthorization(validToken);
    it('should return decoded info', function () {
      let promise = co(strategy.authenticate(this.ctx, 'whatever'));
      return expect(promise).to.eventually.have.property('iss', 'myself');
    });
  });

  context('with query', function () {
    beforeEach(function () {
      this.ctx.request.query = {accessToken: validToken};
      strategy = koaPoliceJwt({secret: secret, query: 'accessToken'});
    });
    it('should read token from query', function () {
      let promise = co(strategy.authenticate(this.ctx, 'whatever'));
      return expect(promise).to.eventually.have.property('iss', 'myself');
    });
  });

  context('with custom getToken logic', function () {
    beforeEach(function () {
      strategy = koaPoliceJwt({secret: secret, getToken: function () {
        return validToken;
      }});
    });
    it('should use provided function', function () {
      let promise = co(strategy.authenticate(this.ctx, 'whatever'));
      return expect(promise).to.eventually.have.property('iss', 'myself');
    });
  });

  context('with function as a secret', function () {
    beforeEach(function () {
      strategy = koaPoliceJwt({secret: function *() {
        return secret;
      }});
    });
    withAuthorization(validToken);
    it('it should generate the secret using the function', function () {
      let promise = co(strategy.authenticate(this.ctx, 'whatever'));
      return expect(promise).to.eventually.have.property('iss', 'myself');
    });
  });

  context('with isRevoked', function () {
    beforeEach(function () {
      strategy = koaPoliceJwt({secret: secret, isRevoked: function *() {
        return true;
      }});
    });
    withAuthorization(validToken);
    it('it should check if token has been revoked', function () {
      return expect(co(strategy.authenticate(this.ctx, 'whatever'))).to.be.rejected;
    });
  });

  context('with processDecoded', function () {
    const extraInfo = 'my_user_from_db';
    beforeEach(function () {
      strategy = koaPoliceJwt({secret: secret, processDecoded: function *(ctx, tokenInfo) {
        tokenInfo.userFromDb = extraInfo;
        return tokenInfo;
      }});
    });
    withAuthorization(validToken);
    it('should process decoded info with processDecoded', function () {
      let promise = co(strategy.authenticate(this.ctx, 'whatever'));
      return expect(promise).to.eventually.have.property('userFromDb', extraInfo);
    });
  });
});
