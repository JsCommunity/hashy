/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

'use strict';

//////////////////////////////////////////////////////////////////////

// Blubird is a very fast and feature complete promise library.
//
// It ships with utilities to deal with generators.
// https://github.com/petkaantonov/bluebird/blob/master/API.md#generators
var Bluebird = require('bluebird');

// To make it work directly from the git repository we are using this
// require but from your project you should just have to do:
//     var hashy = require('hashy');
var hashy = require('..');

//////////////////////////////////////////////////////////////////////

// This value will probably be retrieved from a database.
var hash = '$2a$08$3VbKizuJA1RdlRafd48Kfuf/eKE9kPhP8tOoyHFDmmr/rFkV.d/mO';

// This value will probably be sent by a client (e.g. web browser).
var password = 'test';

Bluebird.coroutine(function *() {
  if (!yield hashy.verify(password, hash)) {
    throw new Error('the password is invalid');
  }

  console.log('the password has been checked, you are now authenticated!');

  // Now we can check if the hash should be recomputed, i.e. if it
  // fits the current security policies (algorithm & options).
  if (hashy.needsRehash(hash))
  {
    hash = yield hashy.hash(password);

    console.log('the hash has been updated:', hash);
  }
})().catch(function (error) {
  // Display any error that might have happened in the chain.
  console.error(error);
});
