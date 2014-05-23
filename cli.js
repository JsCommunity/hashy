'use strict';

//====================================================================

var yargs = require('yargs');
// TESTABILITY: makes yargs throws instead of exiting.
yargs.fail(function (msg) {
  var help = yargs.help();

  if (msg)
  {
    help += '\n' + msg;
  }

  throw help;
});

//--------------------------------------------------------------------

var hashy = require('./');

//====================================================================

module.exports = function cli(argv) {
  var options = yargs
    .usage('Usage: $0 [<option>...]')
    .example('$0 <secret>', 'hash the secret')
    .example('$0 <secret> <hash>', 'verify the secret using the hash')
    .options({
      h: {
        alias: 'help',
        boolean: true,
        describe: 'display this help message',
      },
      v: {
        alias: 'version',
        boolean: true,
        describe: 'display the version number',
      },
    })
    .parse(argv)
  ;

  if (options.help)
  {
    return yargs.help();
  }

  if (options.version)
  {
    var pkg = require('./package');
    return 'Hashy version '+ pkg.version;
  }

  var args = options._;

  if (args.length === 1)
  {
    return hashy.hash(args[0]).then(console.log);
  }

  if (args.length === 2)
  {
    return hashy.verify(args[0], args[1]).then(function (success) {
      if (success)
      {
        return 'ok';
      }

      throw 'not ok';
    });
  }

  throw 'incorrect number of arguments';
};
