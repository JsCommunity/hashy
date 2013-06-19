// @todo Use promises instead of callbacks for lisibility?

var bcrypt = require('bcryptjs');

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
 * @param {function(Error, string)} callback Callback receiving the
 *     error if any and the resulting hash.
 */
var hash = function (password, algo, options, callback) {
	if (algo === BCRYPT)
	{
		bcrypt.hash(
			password,
			options && options.cost || 10,
			callback
		);
	}
	else
	{
		callback(new Error('unsupported algorithm'));
	}
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
	if (hash.startsWith('$2a$'))
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
	var info = getInfo(hash);

	if (info.algo !== algo)
	{
		return true;
	}

	if (algo === BCRYPT)
	{
		var cost = options && options.cost || 10;

		return (info.cost !== cost);
	}

	return false;
};
exports.needsRehash = needsRehash;

/**
 * Checks whether the password and the hash match.
 *
 * @param {string} password The password.
 * @param {string} hash The hash.
 * @param {function(Error, boolean)} callback Callback receiving the
 *     error if any and a boolean.
 */
var verify = function (password, hash, callback) {
	var info = needsRehash(hash);

	if (info.algo === BCRYPT) {
		return bcrypt.compare(password, hash, callback);
	}

	callback(new Error('unsupported algorithm'));
};
exports.verify = verify;
