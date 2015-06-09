'use strict'

/* eslint-env mocha */

// ===================================================================

var hashy = require('./')

// -------------------------------------------------------------------

var expect = require('chai').expect
var Bluebird = require('bluebird')
Bluebird.longStackTraces()

// ===================================================================

var data = [
  {
    value: 'password',
    hash: '$2a$10$3F2S0bh8CO8aVzW/tqyjI.iVQnLNea1YIpNSpS8dmJwUVNXP3D4/y',
    info: {
      algo: 'bcrypt',
      id: '2a',
      options: {
        cost: 10
      }
    }
  },
  {
    value: 'password',
    hash: '$2y$08$YRwXzG/oaZyp6jhsRgUs8eEIyi16nNwi3TtRAJDkQk0YTST.LC/6O',
    info: {
      algo: 'bcrypt',
      id: '2y',
      options: {
        cost: 8
      }
    }
  }
]

// ===================================================================

describe('hash()', function () {
  var hash = hashy.hash

  it('can return a promise', function () {
    return hash('test')
  })

  it('can work with callback', function (done) {
    hash('test', done)
  })

  it('does not creates the same hash twice', function () {
    return Bluebird.all([
      hash('test'),
      hash('test')
    ]).spread(function (hash1, hash2) {
      expect(hash1).to.not.equal(hash2)
    })
  })
})

describe('getInfo()', function () {
  var getInfo = hashy.getInfo

  it('returns the algorithm and options', function () {
    data.forEach(function (datum) {
      expect(getInfo(datum.hash)).to.deep.equal(datum.info)
    })
  })
})

describe('needsRehash()', function () {
  it('returns true if the algorithm or the options differs')
})
