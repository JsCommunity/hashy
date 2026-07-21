#!/usr/bin/env node

"use strict";

// Builds a fresh parser per call instead of reusing the singleton from
// require("yargs"), which would otherwise accumulate aliases/examples
// across repeated main() calls in the same process.
const yargsFactory = require("yargs/yargs");

// --------------------------------------------------------------------

const hashy = require("./");

// ====================================================================

async function main(argv) {
  const yargs = yargsFactory();
  // TESTABILITY: makes yargs throw instead of exiting, including from its
  // built-in --help/--version handling (which prints and would otherwise
  // call process.exit() before main() below ever gets to run).
  yargs.exitProcess(false);
  yargs.fail((msg) => {
    const help = yargs.help();
    throw msg ? `${help}\n${msg}` : help;
  });

  const options = yargs
    .usage("Usage: hashy [<option>...]")
    .example("hashy [ -a <algorithm> ] <secret>", "hash the secret")
    .example("hashy <secret> <hash>", "verify the secret using the hash")
    // Aliases rather than options: yargs already owns "help" and
    // "version" as built-in commands and warns if they are redefined.
    .alias("h", "help")
    .alias("v", "version")
    .options({
      a: {
        default: hashy.DEFAULT_ALGO,
        describe: "algorithm to use for hashing",
      },
      c: {
        alias: "cost",
        describe: "cost for Bcrypt",
      },
    })
    .parse(argv);

  // yargs' built-in --help/--version handling already printed the
  // relevant text as a side effect of .parse() above.
  if (options.help || options.version) {
    return;
  }

  if (options.cost) {
    hashy.options.bcrypt.cost = +options.cost;
  }

  const args = options._;

  if (args.length === 1) {
    console.log(await hashy.hash(args[0], options.a));
    return;
  }

  if (args.length === 2) {
    const [password, hash] = args;

    if (!(await hashy.verify(password, hash))) {
      throw new Error("not ok");
    }

    return hashy.needsRehash(hash, options.a)
      ? "ok but password should be rehashed"
      : "ok";
  }

  throw new Error("incorrect number of arguments");
}
exports = module.exports = main;

// ====================================================================

function prettyFormat(value) {
  if (typeof value === "string") {
    return value;
  }

  if (value instanceof Error) {
    return `${value.message}\n${value.stack}`;
  }

  return JSON.stringify(value, null, 2);
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (value) => {
      if (typeof value === "number" && value % 1 === 0) {
        return process.exit(value);
      }

      if (value !== undefined) {
        console.log(prettyFormat(value));
      }
      process.exit(0);
    },
    (error) => {
      console.error(prettyFormat(error));
      process.exit(1);
    },
  );
}
