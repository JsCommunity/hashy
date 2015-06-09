/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

'use strict'

// ===================================================================

var Bluebird = require('bluebird')

var bcrypt
try {
  bcrypt = (function (bcrypt) {
    var promisify = Bluebird.promisify

    return {
      compare: promisify(bcrypt.compareAsync),
      getRounds: bcrypt.getRounds,
      hash: promisify(bcrypt.hashAsync)
    }
  })(require('bcrypt'))
} catch (_) {
  bcrypt = (function (bcryptjs) {
    var push = [].push

    function promisify (fn, ctx) {
      return function promisified () {
        var args = []
        push.apply(args, arguments)

        return new Bluebird(function (resolve) {
          args.push(resolve)
          fn.apply(ctx, args)
        })
      }
    }

    var HASH_RE = /^\$2a\$(\d+)\$/

    return {
      compare: promisify(bcryptjs.compare),
      getRounds: function (hash) {
        var matches = HASH_RE.exec(hash)
        if (!matches) {
          throw new Error('invalid match')
        }
        return +matches[1]
      },
      hash: promisify(bcryptjs.hash)
    }
  })(require('twin-bcrypt'))
}

// ===================================================================

var has = Object.prototype.hasOwnProperty

function assign (target, source) {
  var i, n, key

  for (i = 1, n = arguments.length; i < n; ++i) {
    source = arguments[i]
    for (key in source) {
      if (has.call(source, key)) {
        target[key] = source[key]
      }
    }
  }

  return target
}

// -------------------------------------------------------------------

var isFunction = (function () {
  var toString = Object.prototype.toString

  var tag = toString.call(function () {})

  return function isFunction (value) {
    return (toString.call(value) === tag)
  }
})()

// -------------------------------------------------------------------

var slice = Array.prototype.slice

// Similar to Bluebird.method(fn) but handle Node callbacks.
function makeAsyncWrapper (fn) {
  return function asyncWrapper () {
    var args = slice.call(arguments)
    var callback

    var n = args.length
    if (n && isFunction(args[--n])) {
      callback = args.pop()
    }

    return Bluebird.try(fn, args, this).nodeify(callback)
  }
}

// ===================================================================

var globalOptions = {}
exports.options = globalOptions

// -------------------------------------------------------------------

var DEFAULT_ALGO = 'bcrypt'

globalOptions.bcrypt = {
  cost: 10
}

// -------------------------------------------------------------------

/**
 * Hashes a password.
 *
 * @param {string} password The password to hash.
 * @param {integer} algo Identifier of the algorithm to use.
 * @param {object} options Options for the algorithm.
 * @param {function} callback Optional callback.
 *
 * @return {object} A promise which will receive the hashed password.
 */
function hash (password, algo, options) {
  algo || (algo = DEFAULT_ALGO)

  if (algo === 'bcrypt') {
    options = assign({}, options, globalOptions.bcrypt)
    return bcrypt.hash(password, options.cost)
  }

  throw new Error('unsupported algorithm')
}
exports.hash = makeAsyncWrapper(hash)

/**
 * Returns information about a hash.
 *
 * @param {string} hash The hash you want to get information from.
 *
 * @return {object} Object containing information about the given
 *     hash: “algo”: the algorithm used, “options” the options used.
 */
function getInfo (hash) {
  // What to do with “$2x$” and “$2y$”?
  if (hash.substring(0, 4) === '$2a$') {
    return {
      algo: 'bcrypt',
      options: {
        cost: bcrypt.getRounds(hash)
      }
    }
  }

  return {
    algo: 'unknown',
    options: {}
  }
}
exports.getInfo = getInfo

/**
 * Checks whether the hash needs to be recomputed.
 *
 * The hash should be recomputed if it does not use the given
 * algorithm and options.
 *
 * @param {string} hash The hash to analyse.
 * @param {integer} algo The algorithm to use.
 * @param {options} options The options to use.
 *
 * @return {boolean} Whether the hash needs to be recomputed.
 */
function needsRehash (hash, algo, options) {
  var info = getInfo(hash)

  algo || (algo = DEFAULT_ALGO)

  if (info.algo !== algo) {
    return true
  }

  if (algo === 'bcrypt') {
    options = assign({}, options, globalOptions.bcrypt)

    return (info.options.cost < options.cost)
  }

  return false
}
exports.needsRehash = needsRehash

/**
 * Checks whether the password and the hash match.
 *
 * @param {string} password The password.
 * @param {string} hash The hash.
 * @param {function} callback Optional callback.
 *
 * @return {object} A promise which will receive a boolean.
 */
function verify (password, hash) {
  var info = getInfo(hash)

  if (info.algo === 'bcrypt') {
    return bcrypt.compare(password, hash)
  }

  throw new Error('unsupported algorithm')
}
exports.verify = makeAsyncWrapper(verify)
