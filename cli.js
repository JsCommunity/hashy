#!/usr/bin/env node

"use strict";

const { parseArgs } = require("node:util");

// --------------------------------------------------------------------

const hashy = require("./");

// ====================================================================

const HELP = `Usage: hashy [<option>...]

Options:
  -a, --algorithm  algorithm to use for hashing  [default: "${hashy.DEFAULT_ALGO}"]
  -c, --cost       cost for Bcrypt
  -h, --help       show help
  -v, --version    show version number

Examples:
  hashy [ -a <algorithm> ] <secret>  hash the secret
  hashy <secret> <hash>              verify the secret using the hash`;

async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        algorithm: { type: "string", short: "a" },
        cost: { type: "string", short: "c" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (error) {
    throw `${HELP}\n${error.message}`;
  }
  const { values: options, positionals: args } = parsed;
  const algorithm = options.algorithm ?? hashy.DEFAULT_ALGO;

  if (options.help) {
    console.log(HELP);
    return;
  }

  if (options.version) {
    console.log(require("./package.json").version);
    return;
  }

  if (options.cost !== undefined) {
    hashy.options.bcrypt.cost = Number(options.cost);
  }

  if (args.length === 1) {
    console.log(await hashy.hash(args[0], algorithm));
    return;
  }

  if (args.length === 2) {
    const [password, hash] = args;

    if (!(await hashy.verify(password, hash))) {
      throw new Error("not ok");
    }

    return hashy.needsRehash(hash, algorithm)
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
