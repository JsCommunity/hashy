"use strict";

module.exports = {
  // A function so lint-staged does not append the staged files: the whole
  // suite runs regardless.
  "*": [() => "npm test", "prettier --ignore-unknown --write"],
  "*.{{,c,m}j,t}s{,x}": "eslint --ignore-pattern '!*'",
};
