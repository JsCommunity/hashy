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
    },
    needsRehash: true
  },
  {
    value: 'password',
    hash: '$2y$08$NVRpJ.42Kt3FM0SWq/.a1uk7U8stm6Ce7EMgooPjBpDZHMiugFVhu',
    info: {
      algo: 'bcrypt',
      id: '2y',
      options: {
        cost: 8
      }
    },
    needsRehash: true
  },
  {
    value: 'password',
    hash: '$2y$11$ddGrBWDagPYovj6dsoUy6OHkeh0wNfQWWhONtPdj7q8qbPX.LtvRW',
    info: {
      algo: 'bcrypt',
      id: '2y',
      options: {
        cost: 11
      }
    },
    needsRehash: false
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
  var needsRehash = hashy.needsRehash

  it('returns true if the algorithm or the options differs', function () {
    data.forEach(function (datum) {
      expect(needsRehash(datum.hash)).to.equal(datum.needsRehash)
    })
  })
})

describe('verify()', function () {
  var verify = hashy.verify

  it('returns whether the password matches the hash', function () {
    return Bluebird.map(data, function (datum) {
      return verify(datum.value, datum.hash).then(function (success) {
        expect(success).to.be.true
      })
    })
  })
})
