var bcrypt = require('bcryptjs');

//////////////////////////////////////////////////////////////////////

var BCRYPT = 1;
exports.BCRYPT = BCRYPT;

var DEFAULT = BCRYPT;
exports.DEFAULT = DEFAULT;

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


var verify = function (password, hash, callback) {
	var info = needsRehash(hash);

	if (info.algo === BCRYPT) {
		return bcrypt.compare(password, hash, callback);
	}

	callback(new Error('unsupported algorithm'));
};
exports.verify = verify;
