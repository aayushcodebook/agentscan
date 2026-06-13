'use strict';

/*
 * Tiny ANSI color helper. No dependency on chalk/colors — a security tool
 * shouldn't pull in a supply chain just to print red text.
 *
 * Colors auto-disable when output isn't a TTY, when NO_COLOR is set, or when
 * --no-color is passed (handled in index.js by toggling enabled).
 */

const state = { enabled: process.stdout.isTTY && !process.env.NO_COLOR };

const CODES = {
  reset: 0,
  bold: 1,
  dim: 2,
  red: 31,
  green: 32,
  yellow: 33,
  blue: 34,
  magenta: 35,
  cyan: 36,
  gray: 90,
  bgRed: 41,
  bgGreen: 42,
  bgYellow: 43
};

function wrap(code, str) {
  if (!state.enabled) return str;
  return `[${code}m${str}[0m`;
}

const c = {
  setEnabled(v) { state.enabled = v; },
  isEnabled() { return state.enabled; },
  red: (s) => wrap(CODES.red, s),
  green: (s) => wrap(CODES.green, s),
  yellow: (s) => wrap(CODES.yellow, s),
  blue: (s) => wrap(CODES.blue, s),
  cyan: (s) => wrap(CODES.cyan, s),
  magenta: (s) => wrap(CODES.magenta, s),
  gray: (s) => wrap(CODES.gray, s),
  bold: (s) => wrap(CODES.bold, s),
  dim: (s) => wrap(CODES.dim, s),
  bgRed: (s) => wrap(CODES.bgRed, s),
  bgGreen: (s) => wrap(CODES.bgGreen, s),
  bgYellow: (s) => wrap(CODES.bgYellow, s)
};

module.exports = c;
