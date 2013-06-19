/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

//////////////////////////////////////////////////////////////////////

var bcrypt = require('bcryptjs');
var Q      = require('q');

//////////////////////////////////////////////////////////////////////

/**
 * Identifier for the bcrypt algorithm.
 *
 * @type {integer}
 */
var BCRYPT = 1;
exports.BCRYPT = BCRYPT;

/**
 * Default algorithm to use for hashing.
 *
 * @type {integer}
 */
var DEFAULT = BCRYPT;
exports.DEFAULT = DEFAULT;

/**
 * Hashes a password.
 *
 * @param {string} password The password to hash.
 * @param {integer} algo Identifier of the algorithm to use.
 * @param {object} options Options for the algorithm.
 *
 * @return {object} A Q promise which will receive the hashed password.
 */
var hash = function (password, algo, options) {
	algo = algo || DEFAULT;

	if (algo === BCRYPT)
	{
		return Q.ninvoke(
			bcrypt,
			'hash',
			password,
			options && options.cost || 10
		);
	}

	return Q.fcall(function () {
		throw new Error('unsupported algorithm');
	});
};
exports.hash = hash;

/**
 * Returns information about a hash.
 *
 * @param {string} hash The hash you want to get information from.
 *
 * @return {object} Object containing information about the given
 *     hash: “algo”: the algorithm used, “options” the options used.
 */
var getInfo = function (hash) {
	// What to do with “$2x$” and “$2y$”?
	if (hash.substring(0, 4) === '$2a$')
	{
		return {
			'algo': BCRYPT,
			'algoName': 'bcrypt',
			'options': {
				'cost': bcrypt.getRounds(hash)
			}
		};
	}

	return {
		'algo': 0,
		'algoName': 'unknown',
		'options': {}
	};
};
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
var needsRehash = function (hash, algo, options) {
	algo = algo || DEFAULT;

	var info = getInfo(hash);

	if (info.algo !== algo)
	{
		return true;
	}

	if (algo === BCRYPT)
	{
		var cost = options && options.cost || 10;

		return (info.options.cost !== cost);
	}

	return false;
};
exports.needsRehash = needsRehash;

/**
 * Checks whether the password and the hash match.
 *
 * @param {string} password The password.
 * @param {string} hash The hash.
 *
 * @return {object} A Q promise which will receive a boolean.
 */
var verify = function (password, hash) {
	var info = getInfo(hash);

	if (info.algo === BCRYPT)
	{
		return Q.ninvoke(bcrypt, 'compare', password, hash);
	}

	return Q.fcall(function () {
		throw new Error('unsupported algorithm');
	});
};
exports.verify = verify;
