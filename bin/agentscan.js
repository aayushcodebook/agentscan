#!/usr/bin/env node
'use strict';

/*
 * agentscan — free, local security scanner for self-hosted AI agents.
 *
 * Zero external dependencies on purpose: a security tool you paste into a
 * terminal should be short enough to read and trust. Everything here uses
 * only Node built-ins, and nothing ever leaves your machine.
 */

const { run } = require('../src/index.js');

run(process.argv.slice(2))
  .then((exitCode) => process.exit(exitCode))
  .catch((err) => {
    console.error('\nagentscan crashed unexpectedly:');
    console.error(err && err.stack ? err.stack : err);
    console.error('\nThis is a bug. Please report it with the message above.');
    process.exit(2);
  });
