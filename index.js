/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

"use strict";

// ===================================================================

const promiseToolbox = require("promise-toolbox");

const asCallback = promiseToolbox.asCallback;
const promisifyAll = promiseToolbox.promisifyAll;

// ===================================================================

// Similar to Bluebird.method(fn) but handle Node callbacks.
const makeAsyncWrapper = (function (push) {
  return function makeAsyncWrapper(fn) {
    return function asyncWrapper() {
      const args = [];
      push.apply(args, arguments);
      let callback;

      const n = args.length;
      if (n && typeof args[n - 1] === "function") {
        callback = args.pop();
      }

      return asCallback.call(
        new Promise(function (resolve) {
          resolve(fn.apply(this, args));
        }),
        callback,
      );
    };
  };
})(Array.prototype.push);

// ===================================================================

const algorithmsById = Object.create(null);
const algorithmsByName = Object.create(null);

const globalOptions = Object.create(null);
exports.options = globalOptions;

let DEFAULT_ALGO;
Object.defineProperty(exports, "DEFAULT_ALGO", {
  enumerable: true,
  get: function () {
    return DEFAULT_ALGO;
  },
});

function registerAlgorithm(algo) {
  const name = algo.name;

  if (algorithmsByName[name]) {
    throw new Error("name " + name + " already taken");
  }
  algorithmsByName[name] = algo;

  algo.ids.forEach(function (id) {
    if (algorithmsById[id]) {
      throw new Error("id " + id + " already taken");
    }
    algorithmsById[id] = algo;
  });

  globalOptions[name] = Object.assign(Object.create(null), algo.defaults);

  if (!DEFAULT_ALGO) {
    DEFAULT_ALGO = name;
  }
}

// -------------------------------------------------------------------

(function (argon2) {
  registerAlgorithm({
    name: "argon2",
    ids: ["argon2d", "argon2i", "argon2id"],
    defaults: require("argon2").defaults,

    getOptions: function (hash, info) {
      let rawOptions = info.options;
      let options = {};

      // Since Argon2 1.3, the version number is encoded in the hash.
      let version;
      if (rawOptions.slice(0, 2) === "v=") {
        version = +rawOptions.slice(2);

        const index = hash.indexOf(rawOptions) + rawOptions.length + 1;
        rawOptions = hash.slice(index, hash.indexOf("$", index));
      }

      rawOptions.split(",").forEach(function (datum) {
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
    needsRehash: argon2.needsRehash,
    verify: function (password, hash) {
      return argon2.verify(hash, password);
    },
  });
})(require("argon2"));

(function (bcrypt) {
  registerAlgorithm({
    name: "bcrypt",
    ids: ["2", "2a", "2b", "2x", "2y"],
    defaults: { cost: 10 },

    getOptions: function (_, info) {
      return {
        cost: +info.options,
      };
    },
    hash: function (password, options) {
      return bcrypt.genSalt(options.cost).then(function (salt) {
        return bcrypt.hash(password, salt);
      });
    },
    needsRehash: function (_, info) {
      const id = info.id;
      if (id !== "2a" && id !== "2b" && id !== "2y") {
        return true;
      }

      // Otherwise, let the default algorithm decides.
    },
    verify: function (password, hash) {
      // See: https://github.com/ncb000gt/node.bcrypt.js/issues/175#issuecomment-26837823
      if (hash.startsWith("$2y$")) {
        hash = "$2a$" + hash.slice(4);
      }

      return bcrypt.compare(password, hash);
    },
  });
})(promisifyAll(require("bcryptjs")));

// -------------------------------------------------------------------

const getHashInfo = (function (HASH_RE) {
  return function getHashInfo(hash) {
    const matches = hash.match(HASH_RE);
    if (!matches) {
      throw new Error("invalid hash " + hash);
    }

    return {
      id: matches[1],
      options: matches[2],
    };
  };
})(/^\$([^$]+)\$([^$]*)\$/);

function getAlgorithmByName(name) {
  const algo = algorithmsByName[name];
  if (!algo) {
    throw new Error("no available algorithm with name " + name);
  }

  return algo;
}

function getAlgorithmFromId(id) {
  const algo = algorithmsById[id];
  if (!algo) {
    throw new Error("no available algorithm with id " + id);
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

  const algoNeedsRehash = getAlgorithmFromId(info.id).needsRehash;
  const result = algoNeedsRehash && algoNeedsRehash(hash, info);
  if (typeof result === "boolean") {
    return result;
  }

  const expected = Object.assign(
    Object.create(null),
    globalOptions[info.algorithm],
    options,
  );
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
