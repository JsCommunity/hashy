"use strict";

/* eslint-env jest */

// ===================================================================

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
    hash:
      "$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc",
    info: {
      algorithm: "argon2",
      id: "argon2i",
      options: {
        memoryCost: 4096,
        parallelism: 1,
        timeCost: 3,
      },
    },
    needsRehash: false,
  },
  "argon2i with version": {
    value: "password",
    hash:
      "$argon2i$v=19$m=4096,t=3,p=1$BHBji9GuMvFc7SrpWucvcQ$7ITF2KM6dkpqGQQKvdMQrfdZ/uhOuiV0A/ZwjCuManM",
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
    needsRehash: false,
  },
};

const forOwn = (object, iteratee) => {
  Object.keys(object).forEach(key => {
    iteratee(object[key], key, object);
  });
};

// ===================================================================

// Sets a small cost for Bcrypt to speed up the tests.
hashy.options.bcrypt.cost = 5;

describe("hash()", function() {
  const hash = hashy.hash;

  it("can return a promise", function() {
    return hash("test");
  });

  it("can work with callback", function(done) {
    hash("test", done);
  });

  it("does not creates the same hash twice", function() {
    return Promise.all([hash("test"), hash("test")]).then(function(hashes) {
      expect(hashes[0]).not.toBe(hashes[1]);
    });
  });
});

describe("getInfo()", function() {
  const getInfo = hashy.getInfo;

  forOwn(data, function(datum, name) {
    describe(name, function() {
      it("returns the algorithm and options", function() {
        expect(getInfo(datum.hash)).toEqual(datum.info);
      });
    });
  });
});

describe("needsRehash()", function() {
  const needsRehash = hashy.needsRehash;

  forOwn(data, function(datum, name) {
    describe(name, function() {
      it("returns true if the algorithm or the options differs", function() {
        expect(needsRehash(datum.hash, datum.info.algorithm)).toBe(
          datum.needsRehash
        );
      });
    });
  });
});

describe("verify()", function() {
  const verify = hashy.verify;

  forOwn(data, function(datum, name) {
    describe(name, function() {
      it("returns whether the password matches the hash", function() {
        return verify(datum.value, datum.hash).then(function(success) {
          expect(success).toBe(true);
        });
      });
    });
  });
});
