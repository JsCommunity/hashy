/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

//////////////////////////////////////////////////////////////////////

// To make it work directly from the git repository we are using this
// require but from your project you should just have to do:
//     var hashy = require('hashy');
var hashy = require('../index');

//////////////////////////////////////////////////////////////////////

// As you can see we are using a promises-based interface instead of
// callbacks.
//
// This helps keeping the functions interfaces as clear as possible
// while making your code easier to read.

// This value will probably be retrieved from a database.
var hash = '$2a$08$3VbKizuJA1RdlRafd48Kfuf/eKE9kPhP8tOoyHFDmmr/rFkV.d/mO';

// This value will probably be sent by a client (e.g. web browser).
var password = 'test';

// First we will check whether they match.
hashy.verify(password, hash)
	.then(function (result) {
		if (!result)
		{
			throw new Error('the password is invalid');
			return;
		}

		// Now we can check if the hash should be recomputed, i.e. if it
		// fits the current security policies (algorithm & options).
		if (hashy.needsRehash(hash))
		{
			return hashy.hash(password).then(function (new_hash) {
				hash = new_hash;

				console.log('the hash has been updated:', hash);
			});
		}
	})
	.then(function () {
		console.log('the password has been checked, you are now authenticated!');
	})
	.fail(function (error) {
		console.error(error);
	})
	.done()
;
