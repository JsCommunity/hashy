/**
 * This file is part of Hashy which is released under the MIT license.
 *
 * @author Julien Fontanet <julien.fontanet@isonoe.net>
 */

"use strict";

// ===================================================================

// To make it work directly from the git repository we are using this
// require but from your project you should just have to do:
//     const hashy = require('hashy')
const hashy = require("..");

// ===================================================================

// This value will probably be retrieved from a database.
let hash = "$2a$08$3VbKizuJA1RdlRafd48Kfuf/eKE9kPhP8tOoyHFDmmr/rFkV.d/mO";

// This value will probably be sent by a client (e.g. web browser).
const password = "test";

(async function () {
  if (!(await hashy.verify(password, hash))) {
    throw new Error("the password is invalid");
  }

  console.log("the password has been checked, you are now authenticated!");

  // Now we can check if the hash should be recomputed, i.e. if it
  // fits the current security policies (algorithm & options).
  if (await hashy.needsRehash(hash)) {
    hash = await hashy.hash(password);

    console.log("the hash has been updated:", hash);
  }
})().catch((error) => {
  // Display any error that might have happened in the chain.
  console.error(error);
});
