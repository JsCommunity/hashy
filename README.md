# Hashy

[![Node compatibility](https://badgen.net/npm/node/hashy)](https://npmjs.org/package/hashy) [![License](https://badgen.net/npm/license/hashy)](https://npmjs.org/package/hashy) [![PackagePhobia](https://badgen.net/packagephobia/install/hashy)](https://packagephobia.com/result?p=hashy)

[![Package Version](https://badgen.net/npm/v/hashy)](https://npmjs.org/package/hashy) [![Build Status](https://github.com/JsCommunity/hashy/actions/workflows/ci.yml/badge.svg)](https://github.com/JsCommunity/hashy/actions/workflows/ci.yml) [![Latest Commit](https://badgen.net/github/last-commit/JsCommunity/hashy)](https://github.com/JsCommunity/hashy/commits/master)

> Hash passwords the right way (Argon2 & bcrypt support)

Hashy is a small [Node.js](https://nodejs.org/) library which aims to do
password hashing _[the correct
way](https://wiki.php.net/rfc/password_hash)_.

It has been heavily inspired by the [PHP password hashing
API](https://www.php.net/manual/en/book.password.php) but, following
the Node.js philosophy, hashing is done asynchronously.

Asynchronous functions return promises, ready to be used with
[`await`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/await),
and also accept [callbacks](#callbacks).

Supported algorithms:

- [Argon2](https://en.wikipedia.org/wiki/Argon2)
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)

## Why a new library?

The other ones I found were too complicated and/or were missing
important features.

The main missing feature is the `needsRehash()` function: cryptography
is a fast-moving science and algorithms can quickly become obsolete or
their parameters need to be adjusted to compensate the performance
increase of recent computers (see [OWASP's recommended work
factors](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).

This is exactly what this function is for: checking whether a hash
uses the correct algorithm (and options) to see if we need to compute
a new hash for this password.

## Install

Installation of the npm package:

```
> npm install hashy
```

## Command line

Hashy also comes with a `hashy` executable, install it globally to use
it from anywhere:

```
> npm install --global hashy
```

Hashing a password:

```
> hashy [ -a <algorithm> ] <secret>
```

Verifying a password against a hash:

```
> hashy <secret> <hash>
```

Use `-c`/`--cost` to change the cost when hashing or verifying with
Bcrypt, and `hashy --help` for the full list of options.

> [!WARNING]
> The secret is visible in your shell history and, while the command
> runs, to other users of the machine (e.g. via `ps`).

A secret starting with `-` must be preceded by `--`, e.g. `hashy -- -secret`.

## How to use it?

First, you may take a look at [the example](https://github.com/JsCommunity/hashy/blob/master/examples/async.js).

> [!IMPORTANT]
> All functions fail on invalid input (unknown algorithm, malformed
> hash…): `hash()` and `verify()` reject, `getInfo()` and
> `needsRehash()` throw. Handle errors with `try`/`catch` as usual.

### Creating a hash

```js
const hash = await hashy.hash(password);
```

`hash()` handles two additional optional parameters:

1. `algo`: which algorithm to use, it defaults to `"argon2"`;
2. `options`: additional options for the current algorithm, for bcrypt
   it defaults to `{ cost: 10 }`, for argon2 to whatever the
   [`argon2`](https://www.npmjs.com/package/argon2) package itself
   defaults to.

> [!NOTE]
> Bcrypt silently truncates passwords over 72 bytes, which means two
> different passwords sharing the same 72-byte prefix would hash (and
> verify) identically. To avoid this pitfall, `hash()` rejects with an
> error rather than truncate silently. `verify()` still accepts them so
> that existing hashes keep working until they are rehashed. If you
> need to support longer passwords, use `argon2` (the default) instead.

### Checking a password against a hash

```js
async function login(user, password) {
  if (!(await hashy.verify(password, user.passwordHash))) {
    return false;
  }

  // The password is known at this point: it's the only time the hash
  // can be upgraded to the current algorithm and options.
  if (hashy.needsRehash(user.passwordHash)) {
    user.passwordHash = await hashy.hash(password);
    await user.save();
  }

  return true;
}
```

`needsRehash()` checks whether the hash uses the current algorithm
(including the Argon2 variant) and options (the bcrypt cost must not be
lower). Like [`hash()`](#creating-a-hash), it handles the optional
`algo` and `options` parameters.

### Getting information about a hash

```js
hashy.getInfo(hash);
// {
//   algorithm: "argon2",
//   id: "argon2id",
//   options: { memoryCost: 65536, parallelism: 4, timeCost: 3, version: 19 },
// }
```

### Changing default options

The default options for a given algorithm are available at `hashy.options[<algo>]`.

```js
// Sets the default cost for bcrypt to 12.
hashy.options.bcrypt.cost = 12;
```

## Alternatives

### Promises

See [the example](https://github.com/JsCommunity/hashy/blob/master/examples/promises.js).

```js
hashy.verify(password, hash).then(function (success) {
  if (success) {
    console.log("you are now authenticated!");
  } else {
    console.warn("invalid password!");
  }
}, console.error);
```

### Callbacks

The callback is passed last, after the optional parameters. See [the example](https://github.com/JsCommunity/hashy/blob/master/examples/callbacks.js).

```js
hashy.verify(password, hash, function (error, success) {
  if (error) {
    return console.error(error);
  }

  if (success) {
    console.log("you are now authenticated!");
  } else {
    console.warn("invalid password!");
  }
});
```

## Contributing

Contributions are _very_ welcome, either on the documentation or on
the code.

You may:

- report any [issue](https://github.com/JsCommunity/hashy/issues)
  you've encountered;
- fork and create a pull request.

## License

Hashy is released under the [MIT
license](https://en.wikipedia.org/wiki/MIT_License).
