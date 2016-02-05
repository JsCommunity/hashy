'use strict'

/* eslint-env mocha */

// ===================================================================

require('native-promise-only')
var expect = require('chai').expect

var hashy = require('./')

// ===================================================================

var data = [
  {
    value: 'password',
    hash: '$2y$04$bCdlo4cUGt5.DpaorjzbN.XUX46/YNj4iKsdTvSQ3UE0pleNR2rjS',
    info: {
      algorithm: 'bcrypt',
      id: '2y',
      options: {
        cost: 4
      }
    },
    needsRehash: true
  },
  {
    value: 'password',
    hash: '$2y$05$P2ZY1eZ3oex3LZJ9bGuRnugsVeq6AXy2wlasiKmYamgDEl6w2dRMG',
    info: {
      algorithm: 'bcrypt',
      id: '2y',
      options: {
        cost: 5
      }
    },
    needsRehash: false
  },
  {
    value: 'password',
    hash: '$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc',
    info: {
      algorithm: 'argon2',
      id: 'argon2i',
      options: {
        memoryCost: 12,
        parallelism: 1,
        timeCost: 3
      }
    },
    needsRehash: false
  }
]

// ===================================================================

// Sets a small cost for Bcrypt to speed up the tests.
hashy.options.bcrypt.cost = 5

describe('hash()', function () {
  var hash = hashy.hash

  it('can return a promise', function () {
    return hash('test')
  })

  it('can work with callback', function (done) {
    hash('test', done)
  })

  it('does not creates the same hash twice', function () {
    return Promise.all([
      hash('test'),
      hash('test')
    ]).then(function (hashes) {
      expect(hashes[0]).to.not.equal(hashes[1])
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
      expect(needsRehash(datum.hash, datum.info.algorithm)).to.equal(datum.needsRehash)
    })
  })
})

describe('verify()', function () {
  var verify = hashy.verify

  it('returns whether the password matches the hash', function () {
    return Promise.all(data.map(function (datum) {
      return verify(datum.value, datum.hash).then(function (success) {
        expect(success).to.be.true
      })
    }))
  })
})
