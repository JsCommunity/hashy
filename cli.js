'use strict';

//====================================================================

var yargs = require('yargs');

//--------------------------------------------------------------------

var hashy = require('./');

//====================================================================

module.exports = function cli(argv) {
  var options = yargs
    .usage('Usage: $0 [<option>...]')
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
    .check(function (options) {
      if (options.help)
      {
        throw '';
      }
    })
    .parse(argv)
  ;

  if (options.version)
  {
    var pkg = require('./package');
    console.log('Hashy version '+ pkg.version);
    return;
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
