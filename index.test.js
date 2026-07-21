"use strict";

const { describe, it } = require("node:test");
const assert = require("assert");

const hashy = require("./");

// ===================================================================

const data = {
  "bcrypt 1": {
    value: "password",
    hash: "$2y$04$bCdlo4cUGt5.DpaorjzbN.XUX46/YNj4iKsdTvSQ3UE0pleNR2rjS",
    info: {
      algorithm: "bcrypt",
      id: "2y",
      options: {
        cost: 4,
      },
    },
    needsRehash: true,
  },
  "bcrypt 2": {
    value: "password",
    hash: "$2y$05$P2ZY1eZ3oex3LZJ9bGuRnugsVeq6AXy2wlasiKmYamgDEl6w2dRMG",
    info: {
      algorithm: "bcrypt",
      id: "2y",
      options: {
        cost: 5,
      },
    },
    needsRehash: false,
  },
  argon2i: {
    value: "password",
    hash: "$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
    info: {
      algorithm: "argon2",
      id: "argon2i",
      options: {
        memoryCost: 4096,
        parallelism: 1,
        timeCost: 3,
      },
    },
    needsRehash: true,
  },
  "argon2i with version": {
    value: "password",
    hash: "$argon2i$v=19$m=4096,t=3,p=1$BHBji9GuMvFc7SrpWucvcQ$7ITF2KM6dkpqGQQKvdMQrfdZ/uhOuiV0A/ZwjCuManM",
    info: {
      algorithm: "argon2",
      id: "argon2i",
      options: {
        memoryCost: 4096,
        parallelism: 1,
        timeCost: 3,
        version: 19,
      },
    },
    needsRehash: true,
  },
  "outdated argon2id": {
    value: "password",
    hash: "$argon2id$v=19$m=4096,t=3,p=1$y+oVGwJBgBWCU7nx3AJHFw$Athwv027c/e5qcddK4MZ30stAkkDfugD8VeB+3R2lJY",
    info: {
      algorithm: "argon2",
      id: "argon2id",
      options: {
        memoryCost: 4096,
        parallelism: 1,
        timeCost: 3,
        version: 19,
      },
    },
    needsRehash: true,
  },
  argon2id: {
    value: "password",
    hash: "$argon2id$v=19$m=65536,t=3,p=4$Iz7J5To/Eum0iDVAwfYSoQ$rZPYTyvAjdgmbdeRknwGS5ezhfeGCcUl07RVo7caa2o",
    info: {
      algorithm: "argon2",
      id: "argon2id",
      options: {
        memoryCost: 65536,
        parallelism: 4,
        timeCost: 3,
        version: 19,
      },
    },
    needsRehash: false,
  },
};

const forOwn = (object, iteratee) => {
  Object.keys(object).forEach((key) => {
    iteratee(object[key], key, object);
  });
};

// ===================================================================

// Sets a small cost for Bcrypt to speed up the tests.
hashy.options.bcrypt.cost = 5;

describe("hash()", function () {
  const hash = hashy.hash;

  it("can return a promise", function () {
    return hash("test");
  });

  it("can work with callback", function () {
    return new Promise(function (resolve, reject) {
      hash("test", function (error, hash) {
        if (error) {
          return reject(error);
        }
        resolve(hash);
      });
    });
  });

  it("does not creates the same hash twice", function () {
    return Promise.all([hash("test"), hash("test")]).then(function (hashes) {
      assert.notStrictEqual(hashes[0], hashes[1]);
    });
  });

  it("can be verified", function () {
    return hash("test").then((hash) => hashy.verify("test", hash));
  });

  it("rejects for an unknown algorithm", function () {
    return hash("test", "does-not-exist").then(
      function () {
        throw new Error("expected the promise to be rejected");
      },
      function (error) {
        assert.match(error.message, /no available algorithm with name/);
      },
    );
  });

  it("propagates errors to the callback", function () {
    return new Promise(function (resolve, reject) {
      hash("test", "does-not-exist", function (error) {
        if (error === undefined) {
          return reject(new Error("expected an error"));
        }
        try {
          assert.match(error.message, /no available algorithm with name/);
          resolve();
        } catch (assertionError) {
          reject(assertionError);
        }
      });
    });
  });
});

describe("bcrypt password length limit", function () {
  const longPassword = "a".repeat(73);

  it("hash() rejects passwords over 72 bytes", function () {
    return hashy.hash(longPassword, "bcrypt").then(
      function () {
        throw new Error("expected the promise to be rejected");
      },
      function (error) {
        assert.match(error.message, /72 bytes/);
      },
    );
  });

  it("verify() rejects passwords over 72 bytes", function () {
    return hashy.verify(longPassword, data["bcrypt 2"].hash).then(
      function () {
        throw new Error("expected the promise to be rejected");
      },
      function (error) {
        assert.match(error.message, /72 bytes/);
      },
    );
  });
});

describe("getInfo()", function () {
  const getInfo = hashy.getInfo;

  forOwn(data, function (datum, name) {
    describe(name, function () {
      it("returns the algorithm and options", function () {
        assert.deepStrictEqual(getInfo(datum.hash), datum.info);
      });
    });
  });

  it("throws for a malformed hash", function () {
    assert.throws(function () {
      getInfo("not-a-hash");
    }, /invalid hash/);
  });

  it("throws for an unknown algorithm id", function () {
    assert.throws(function () {
      getInfo("$does-not-exist$options$rest");
    }, /no available algorithm with id/);
  });
});

describe("needsRehash()", function () {
  const needsRehash = hashy.needsRehash;

  forOwn(data, function (datum, name) {
    describe(name, function () {
      it("returns true if the algorithm or the options differs", function () {
        assert.strictEqual(
          needsRehash(datum.hash, datum.info.algorithm),
          datum.needsRehash,
        );
      });
    });
  });

  it("returns true when a different algorithm is requested", function () {
    assert.strictEqual(needsRehash(data.argon2id.hash, "bcrypt"), true);
  });

  it("forces a rehash for legacy Bcrypt ids", function () {
    // ids other than 2a, 2b and 2y are always considered outdated,
    // regardless of cost.
    const hash = data["bcrypt 2"].hash.replace("$2y$", "$2$");
    assert.strictEqual(needsRehash(hash, "bcrypt"), true);
  });

  it("respects custom global options for argon2", function () {
    return hashy
      .hash("test")
      .then(function (hash) {
        // Well above argon2's own default, whatever it currently is.
        hashy.options.argon2.memoryCost = 1 << 20;
        assert.strictEqual(needsRehash(hash, "argon2"), true);
      })
      .finally(function () {
        delete hashy.options.argon2.memoryCost;
      });
  });
});

describe("verify()", function () {
  const verify = hashy.verify;

  forOwn(data, function (datum, name) {
    describe(name, function () {
      it("returns whether the password matches the hash", function () {
        return verify(datum.value, datum.hash).then(function (success) {
          assert.strictEqual(success, true);
        });
      });
    });
  });

  it("can work with callback", function () {
    return new Promise(function (resolve, reject) {
      verify(
        data.argon2id.value,
        data.argon2id.hash,
        function (error, success) {
          if (error) {
            return reject(error);
          }
          try {
            assert.strictEqual(success, true);
            resolve();
          } catch (assertionError) {
            reject(assertionError);
          }
        },
      );
    });
  });
});
