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
      algo: 'bcrypt',
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
      algo: 'bcrypt',
      id: '2y',
      options: {
        cost: 5
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
      expect(needsRehash(datum.hash)).to.equal(datum.needsRehash)
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
