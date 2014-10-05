/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

'use strict';

//====================================================================

var Promise = require('bluebird');
var bcrypt = Promise.promisifyAll(require('bcrypt'));

//====================================================================

var has = Object.prototype.hasOwnProperty;
has = has.call.bind(has);

function assign(target, source) {
  var i, n, key;

  for (i = 1, n = arguments.length; i < n; ++i)
  {
    source = arguments[i];
    for (key in source)
    {
      if (has(source, key))
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
  toString = toString.call.bind(toString);

  var tag = toString(function () {});

  return function isFunction(value) {
    return (toString(value) === tag);
  };
})();

//--------------------------------------------------------------------

function error(value, callback) {
  return Promise.reject(new Error(value)).nodeify(callback);
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
function hash(password, algo, options, callback) {
  if (!isFunction(callback))
  {
    if (isFunction(options))
    {
      callback = options;
      options = null;
    }
    else if (isFunction(algo))
    {
      callback = algo;
      algo = null;
    }
  }

  algo = algo || DEFAULT;

  if (algo === BCRYPT)
  {
    options = assign({}, options, globalOptions[BCRYPT]);

    return bcrypt.genSaltAsync(options.cost).then(function (salt) {
      return bcrypt.hashAsync(password, salt);
    }).nodeify(callback);
  }

  return error('unsupported algorithm', callback);
}
exports.hash = hash;

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
function verify(password, hash, callback) {
  var info = getInfo(hash);

  if (info.algo === BCRYPT)
  {
    return bcrypt.compareAsync(password, hash).nodeify(callback);
  }

  return error('unsupported algorithm', callback);
}
exports.verify = verify;
