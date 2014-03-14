'use strict';

//====================================================================

var hashy = require('./');

//--------------------------------------------------------------------

var expect = require('chai').expect;

//====================================================================

describe('hash()', function () {
  it('hashes a password', function () {
    return hashy.hash('test').then(function (hash) {
      expect(hash).to.equal('$2a$08$3VbKizuJA1RdlRafd48Kfuf/eKE9kPhP8tOoyHFDmmr/rFkV.d/mO');
    });
  });
});
