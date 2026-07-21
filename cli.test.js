"use strict";

const { describe, it } = require("node:test");
const assert = require("assert");

const cli = require("./cli.js");
const hashy = require("./index.js");

// ===================================================================

// Sets a small cost for Bcrypt to speed up the tests.
hashy.options.bcrypt.cost = 4;

// `cli(["-a", "algo", "<secret>"])` logs the hash instead of resolving
// with it, so tests that need the produced hash capture stdout.
function captureLog(fn) {
  const original = console.log;
  let output;
  console.log = function (value) {
    output = value;
  };

  return Promise.resolve()
    .then(fn)
    .then(
      function () {
        console.log = original;
        return output;
      },
      function (error) {
        console.log = original;
        throw error;
      },
    );
}

// ===================================================================

describe("cli", function () {
  it("hashes a password", function () {
    return captureLog(() => cli(["secret"])).then(function (output) {
      assert.match(output, /^\$argon2id\$/);
    });
  });

  it("supports -a to select the algorithm", function () {
    return captureLog(() => cli(["-a", "bcrypt", "secret"])).then(
      function (output) {
        assert.match(output, /^\$2[aby]\$04\$/);
      },
    );
  });

  it("supports -c to set the Bcrypt cost", function () {
    return captureLog(() => cli(["-a", "bcrypt", "-c", "5", "secret"])).then(
      function (output) {
        assert.match(output, /^\$2[aby]\$05\$/);
      },
    );
  });

  it("verifies a matching password/hash pair", function () {
    return captureLog(() => cli(["-a", "bcrypt", "secret"]))
      .then((hash) => cli(["-a", "bcrypt", "secret", hash]))
      .then(function (result) {
        assert.strictEqual(result, "ok");
      });
  });

  it("reports when the hash should be rehashed", function () {
    return captureLog(() => cli(["-a", "bcrypt", "secret"]))
      .then((hash) => cli(["secret", hash]))
      .then(function (result) {
        assert.strictEqual(result, "ok but password should be rehashed");
      });
  });

  it("rejects on a wrong password", function () {
    return captureLog(() => cli(["-a", "bcrypt", "secret"]))
      .then((hash) => cli(["wrong", hash]))
      .then(
        function () {
          throw new Error("expected verification to fail");
        },
        function (error) {
          assert.strictEqual(error.message, "not ok");
        },
      );
  });

  it("rejects on an incorrect number of arguments", function () {
    return cli([]).then(
      function () {
        throw new Error("expected the call to be rejected");
      },
      function (error) {
        assert.match(error.message, /incorrect number of arguments/);
      },
    );
  });

  it("displays the help message", function () {
    return captureLog(() => cli(["--help"])).then(function (output) {
      assert.match(output, /Usage: hashy/);
    });
  });

  it("displays the version number", function () {
    return captureLog(() => cli(["--version"])).then(function (output) {
      assert.strictEqual(output, require("./package.json").version);
    });
  });

  it("does not accumulate aliases across repeated calls", function () {
    return captureLog(() => cli(["secret"]))
      .then(() => captureLog(() => cli(["secret"])))
      .then(() => captureLog(() => cli(["--help"])))
      .then(function (output) {
        assert.strictEqual(output.match(/--help/g).length, 1);
      });
  });
});
