# Hashy

Hashy is small [node.js](http://nodejs.org/) library which aims to do
passwords hashing *[the correct
way](https://wiki.php.net/rfc/password_hash)*.

It has been heavily inspired by the new [PHP password hashing
API](http://www.php.net/manual/en/book.password.php) but, following
the node.js philosophy, hashing is done asynchronously.

Furthermore, to make the interfaces as easy to use as possible, async
functions do not rely on callbacks but return
[Q](https://github.com/kriskowal/q)
[promises](https://github.com/kriskowal/q).

## Why a new library?

The other ones I found were too complicated and/or were missing
important features.

The main missing feature is the `needRehash()` function: cryptography
is a fast-moving science and algorithms can quickly become obsolete or
their parameters needs to be adjusted to compensate the performance
increase of recent computers (e.g. [bcrypt cost
factor](http://phpmaster.com/why-you-should-use-bcrypt-to-hash-stored-passwords/)).

This is exactly what this function is for: checking whether a hash
uses the correct algorithm (and options) to see if we need to compute
a new hash for this password.

## How to use it?

Just take a look at [the available example](https://github.com/julien-f/nodejs-hashy/blob/master/examples/basic.js).

## License

Hashy is released under the [MIT
license](https://en.wikipedia.org/wiki/MIT_License).
