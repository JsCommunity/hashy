/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

'use strict';

//====================================================================

var Bluebird = require('bluebird');
var bcrypt = Bluebird.promisifyAll(require('bcrypt'));

//====================================================================

var has = Object.prototype.hasOwnProperty;

function assign(target, source) {
  var i, n, key;

  for (i = 1, n = arguments.length; i < n; ++i)
  {
    source = arguments[i];
    for (key in source)
    {
      if (has.call(source, key))
      {
        target[key] = source[key];
      }
    }
  }

  return target;
}

//--------------------------------------------------------------------

var isFunction = (function () {
  var toString = Object.prototype.toString;

  var tag = toString.call(function () {});

  return function isFunction(value) {
    return (toString.call(value) === tag);
  };
})();

//--------------------------------------------------------------------

var slice = Array.prototype.slice;

// Similar to Bluebird.method(fn) but handle Node callbacks.
function makeAsyncWrapper(fn) {
  return function asyncWrapper() {
    var args = slice.call(arguments);
    var callback;

    var n = args.length;
    if (n && isFunction(args[--n])) {
      callback = args.pop();
    }

    return Bluebird.try(fn, args, this).nodeify(callback);
  };
}

//====================================================================

var globalOptions = {};
exports.options = globalOptions;

//--------------------------------------------------------------------

/**
 * Identifier for the bcrypt algorithm.
 *
 * @type {integer}
 */
var BCRYPT = exports.BCRYPT = 1;

globalOptions[BCRYPT] = {
  cost: 10,
};

/**
 * Default algorithm to use for hashing.
 *
 * @type {integer}
 */
var DEFAULT = exports.DEFAULT = BCRYPT;

//--------------------------------------------------------------------

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
function hash(password, algo, options) {
  algo = algo || DEFAULT;

  if (algo === BCRYPT)
  {
    options = assign({}, options, globalOptions[BCRYPT]);
    return bcrypt.genSaltAsync(options.cost).then(function (salt) {
      return bcrypt.hashAsync(password, salt);
    });
  }

  throw new Error('unsupported algorithm');
}
exports.hash = makeAsyncWrapper(hash);

/**
 * Returns information about a hash.
 *
 * @param {string} hash The hash you want to get information from.
 *
 * @return {object} Object containing information about the given
 *     hash: “algo”: the algorithm used, “options” the options used.
 */
function getInfo(hash) {
  // What to do with “$2x$” and “$2y$”?
  if (hash.substring(0, 4) === '$2a$')
  {
    return {
      algo: BCRYPT,
      algoName: 'bcrypt',
      options: {
        cost: bcrypt.getRounds(hash)
      }
    };
  }

  return {
    algo: 0,
    algoName: 'unknown',
    options: {}
  };
}
exports.getInfo = getInfo;

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
function needsRehash(hash, algo, options) {
  algo = algo || DEFAULT;

  var info = getInfo(hash);

  if (info.algo !== algo)
  {
    return true;
  }

  if (algo === BCRYPT)
  {
    options = assign({}, options, globalOptions[BCRYPT]);

    return (info.options.cost !== options.cost);
  }

  return false;
}
exports.needsRehash = needsRehash;

/**
 * Checks whether the password and the hash match.
 *
 * @param {string} password The password.
 * @param {string} hash The hash.
 * @param {function} callback Optional callback.
 *
 * @return {object} A promise which will receive a boolean.
 */
function verify(password, hash) {
  var info = getInfo(hash);

  if (info.algo === BCRYPT)
  {
    return bcrypt.compareAsync(password, hash);
  }

  throw new Error('unsupported algorithm');
}
exports.verify = makeAsyncWrapper(verify);
