/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

"use strict";

// ===================================================================

// Similar to Bluebird.method(fn) but handle Node callbacks.
function makeAsyncWrapper(fn) {
  return function asyncWrapper(...args) {
    const callback =
      typeof args[args.length - 1] === "function" ? args.pop() : undefined;

    const promise = (async () => fn(...args))();
    if (callback !== undefined) {
      promise.then((value) => callback(undefined, value), callback);
    }
    return promise;
  };
}

// ===================================================================

const algorithmsById = Object.create(null);
const algorithmsByName = Object.create(null);

const globalOptions = Object.create(null);
exports.options = globalOptions;

let DEFAULT_ALGO;
Object.defineProperty(exports, "DEFAULT_ALGO", {
  enumerable: true,
  get: () => DEFAULT_ALGO,
});

function registerAlgorithm(algo) {
  const { name } = algo;

  if (algorithmsByName[name]) {
    throw new Error(`name ${name} already taken`);
  }
  algorithmsByName[name] = algo;

  algo.ids.forEach((id) => {
    if (algorithmsById[id]) {
      throw new Error(`id ${id} already taken`);
    }
    algorithmsById[id] = algo;
  });

  globalOptions[name] = Object.assign(Object.create(null), algo.defaults);

  if (!DEFAULT_ALGO) {
    DEFAULT_ALGO = name;
  }
}

// -------------------------------------------------------------------

const argon2 = require("argon2");

registerAlgorithm({
  name: "argon2",
  ids: ["argon2d", "argon2i", "argon2id"],

  getOptions: (hash, info) => {
    let rawOptions = info.options;
    let options = {};

    // Since Argon2 1.3, the version number is encoded in the hash.
    let version;
    if (rawOptions.slice(0, 2) === "v=") {
      version = +rawOptions.slice(2);

      const index = hash.indexOf(rawOptions) + rawOptions.length + 1;
      rawOptions = hash.slice(index, hash.indexOf("$", index));
    }

    rawOptions.split(",").forEach((datum) => {
      const index = datum.indexOf("=");
      if (index === -1) {
        options[datum] = true;
      } else {
        options[datum.slice(0, index)] = datum.slice(index + 1);
      }
    });

    options = {
      memoryCost: +options.m,
      parallelism: +options.p,
      timeCost: +options.t,
    };
    if (version !== undefined) {
      options.version = version;
    }
    return options;
  },
  hash: argon2.hash,
  // Delegates to argon2's own comparison against `expected` (the
  // configured global/per-call options) instead of hardcoding a copy
  // of argon2's defaults: whatever is left unset is compared against
  // argon2's own current defaults directly.
  needsRehash: (hash, info, expected) => argon2.needsRehash(hash, expected),
  verify: (password, hash) => argon2.verify(hash, password),
});

const bcrypt = require("bcryptjs");

// Bcrypt silently truncates passwords over 72 bytes: two different
// passwords sharing the same 72-byte prefix would hash (and verify)
// identically. Reject upfront rather than let that go unnoticed.
function checkBcryptPasswordLength(password) {
  if (bcrypt.truncates(password)) {
    throw new Error(
      "bcrypt cannot handle passwords over 72 bytes, use a different algorithm (e.g. argon2) or pre-hash the password",
    );
  }
}

registerAlgorithm({
  name: "bcrypt",
  ids: ["2", "2a", "2b", "2x", "2y"],
  defaults: { cost: 10 },

  getOptions: (_, { options }) => ({ cost: +options }),
  hash: async (password, options) => {
    checkBcryptPasswordLength(password);
    return bcrypt.hash(password, await bcrypt.genSalt(options.cost));
  },
  needsRehash: (_, { id }) => {
    if (id !== "2a" && id !== "2b" && id !== "2y") {
      return true;
    }

    // Otherwise, let the default algorithm decides.
  },
  verify: (password, hash) => {
    checkBcryptPasswordLength(password);

    // See: https://github.com/ncb000gt/node.bcrypt.js/issues/175#issuecomment-26837823
    if (hash.startsWith("$2y$")) {
      hash = "$2a$" + hash.slice(4);
    }

    return bcrypt.compare(password, hash);
  },
});

// -------------------------------------------------------------------

const HASH_RE = /^\$([^$]+)\$([^$]*)\$/;

function getHashInfo(hash) {
  const matches = hash.match(HASH_RE);
  if (!matches) {
    throw new Error(`invalid hash ${hash}`);
  }

  return {
    id: matches[1],
    options: matches[2],
  };
}

function getAlgorithmByName(name) {
  const algo = algorithmsByName[name];
  if (!algo) {
    throw new Error(`no available algorithm with name ${name}`);
  }

  return algo;
}

function getAlgorithmFromId(id) {
  const algo = algorithmsById[id];
  if (!algo) {
    throw new Error(`no available algorithm with id ${id}`);
  }

  return algo;
}

function getAlgorithmFromHash(hash) {
  return getAlgorithmFromId(getHashInfo(hash).id);
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
function hash(password, algo, options) {
  algo = getAlgorithmByName(algo || DEFAULT_ALGO);

  return algo.hash(
    password,
    Object.assign(Object.create(null), globalOptions[algo.name], options),
  );
}
exports.hash = makeAsyncWrapper(hash);

/**
 * Returns information about a hash.
 *
 * @param {string} hash The hash you want to get information from.
 *
 * @return {object} Object containing information about the given
 *     hash: “algorithm”: the algorithm used, “options” the options
 *     used.
 */
function getInfo(hash) {
  const info = getHashInfo(hash);
  const algo = getAlgorithmFromId(info.id);
  info.algorithm = algo.name;
  info.options = algo.getOptions(hash, info);

  return info;
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
  const info = getInfo(hash);

  if (info.algorithm !== (algo || DEFAULT_ALGO)) {
    return true;
  }

  const expected = Object.assign(
    Object.create(null),
    globalOptions[info.algorithm],
    options,
  );

  const algoNeedsRehash = getAlgorithmFromId(info.id).needsRehash;
  const result = algoNeedsRehash && algoNeedsRehash(hash, info, expected);
  if (typeof result === "boolean") {
    return result;
  }

  const actual = info.options;

  for (const prop in actual) {
    const value = actual[prop];
    if (typeof value === "number" && value < expected[prop]) {
      return true;
    }
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
  return getAlgorithmFromHash(hash).verify(password, hash);
}
exports.verify = makeAsyncWrapper(verify);
