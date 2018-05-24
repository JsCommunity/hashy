/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

'use strict'

// ===================================================================

var promiseToolbox = require('promise-toolbox')

var asCallback = promiseToolbox.asCallback
var promisifyAll = promiseToolbox.promisifyAll

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

function forArray (array, iteratee) {
  for (var i = 0, n = array.length; i < n; ++i) {
    iteratee(array[i], i, array)
  }
}

var isFunction = (function (toString) {
  var tag = toString.call(toString)

  return function isFunction (value) {
    return (toString.call(value) === tag)
  }
})(Object.prototype.toString)

// Similar to Bluebird.method(fn) but handle Node callbacks.
var makeAsyncWrapper = (function (push) {
  return function makeAsyncWrapper (fn) {
    return function asyncWrapper () {
      var args = []
      push.apply(args, arguments)
      var callback

      var n = args.length
      if (n && isFunction(args[n - 1])) {
        callback = args.pop()
      }

      return asCallback.call(new Promise(function (resolve) {
        resolve(fn.apply(this, args))
      }), callback)
    }
  }
})(Array.prototype.push)

function startsWith (string, search) {
  return string.lastIndexOf(search, 0) === 0
}

// ===================================================================

var algorithmsById = Object.create(null)
var algorithmsByName = Object.create(null)

var globalOptions = Object.create(null)
exports.options = globalOptions

var DEFAULT_ALGO
Object.defineProperty(exports, 'DEFAULT_ALGO', {
  enumerable: true,
  get: function () {
    return DEFAULT_ALGO
  }
})

function registerAlgorithm (algo) {
  var name = algo.name

  if (algorithmsByName[name]) {
    throw new Error('name ' + name + ' already taken')
  }
  algorithmsByName[name] = algo

  forArray(algo.ids, function (id) {
    if (algorithmsById[id]) {
      throw new Error('id ' + id + ' already taken')
    }
    algorithmsById[id] = algo
  })

  globalOptions[name] = assign(Object.create(null), algo.defaults)

  if (!DEFAULT_ALGO) {
    DEFAULT_ALGO = name
  }
}

// -------------------------------------------------------------------

;(function (bcrypt) {
  registerAlgorithm({
    name: 'bcrypt',
    ids: [ '2', '2a', '2b', '2x', '2y' ],
    defaults: { cost: 10 },

    getOptions: function (_, info) {
      return {
        cost: +info.options
      }
    },
    hash: function (password, options) {
      return bcrypt.genSalt(options.cost).then(function (salt) {
        return bcrypt.hash(password, salt)
      })
    },
    needsRehash: function (_, info) {
      var id = info.id
      if (
        id !== '2a' &&
        id !== '2b' &&
        id !== '2y'
      ) {
        return true
      }

      // Otherwise, let the default algorithm decides.
    },
    verify: function (password, hash) {
      // See: https://github.com/ncb000gt/node.bcrypt.js/issues/175#issuecomment-26837823
      if (startsWith(hash, '$2y$')) {
        hash = '$2a$' + hash.slice(4)
      }

      return bcrypt.compare(password, hash)
    }
  })
})(promisifyAll(function () {
  try {
    return require('bcrypt')
  } catch (_) {
    return require('bcryptjs')
  }
}()))

try {
  ;(function (argon2) {
    registerAlgorithm({
      name: 'argon2',
      ids: [ 'argon2d', 'argon2i' ],
      defaults: require('argon2').defaults,

      getOptions: function (hash, info) {
        var rawOptions = info.options
        var options = {}

        // Since Argon2 1.3, the version number is encoded in the hash.
        var version
        if (rawOptions.slice(0, 2) === 'v=') {
          version = +rawOptions.slice(2)

          var index = hash.indexOf(rawOptions) + rawOptions.length + 1
          rawOptions = hash.slice(index, hash.indexOf('$', index))
        }

        rawOptions.split(',').forEach(function (datum) {
          var index = datum.indexOf('=')
          if (index === -1) {
            options[datum] = true
          } else {
            options[datum.slice(0, index)] = datum.slice(index + 1)
          }
        })

        options = {
          memoryCost: +options.m,
          parallelism: +options.p,
          timeCost: +options.t
        }
        if (version !== undefined) {
          options.version = version
        }
        return options
      },
      hash: argon2.hash,
      verify: function (password, hash) {
        return argon2.verify(hash, password)
      }
    })
  })(require('argon2'))
} catch (_) {}

// -------------------------------------------------------------------

var getHashInfo = (function (HASH_RE) {
  return function getHashInfo (hash) {
    var matches = hash.match(HASH_RE)
    if (!matches) {
      throw new Error('invalid hash ' + hash)
    }

    return {
      id: matches[1],
      options: matches[2]
    }
  }
})(/^\$([^$]+)\$([^$]*)\$/)

function getAlgorithmByName (name) {
  var algo = algorithmsByName[name]
  if (!algo) {
    throw new Error('no available algorithm with name ' + name)
  }

  return algo
}

function getAlgorithmFromId (id) {
  var algo = algorithmsById[id]
  if (!algo) {
    throw new Error('no available algorithm with id ' + id)
  }

  return algo
}

function getAlgorithmFromHash (hash) {
  return getAlgorithmFromId(getHashInfo(hash).id)
}

// ===================================================================

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
  algo = getAlgorithmByName(algo || DEFAULT_ALGO)

  return algo.hash(
    password,
    assign(Object.create(null), globalOptions[algo.name], options)
  )
}
exports.hash = makeAsyncWrapper(hash)

/**
 * Returns information about a hash.
 *
 * @param {string} hash The hash you want to get information from.
 *
 * @return {object} Object containing information about the given
 *     hash: “algorithm”: the algorithm used, “options” the options
 *     used.
 */
function getInfo (hash) {
  var info = getHashInfo(hash)
  var algo = getAlgorithmFromId(info.id)
  info.algorithm = algo.name
  info.options = algo.getOptions(hash, info)

  return info
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

  if (info.algorithm !== (algo || DEFAULT_ALGO)) {
    return true
  }

  var algoNeedsRehash = getAlgorithmFromId(info.id).needsRehash
  var result = algoNeedsRehash && algoNeedsRehash(hash, info)
  if (typeof result === 'boolean') {
    return result
  }

  var expected = assign(Object.create(null), globalOptions[info.algorithm], options)
  var actual = info.options

  for (var prop in actual) {
    var value = actual[prop]
    if (
      typeof value === 'number' &&
      value < expected[prop]
    ) {
      return true
    }
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
  return getAlgorithmFromHash(hash).verify(password, hash)
}
exports.verify = makeAsyncWrapper(verify)
