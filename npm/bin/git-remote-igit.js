#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const executable = path.join(__dirname, '..', 'vendor', `git-remote-igit${process.platform === 'win32' ? '.exe' : ''}`);
const result = spawnSync(executable, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) { console.error(result.error.message); process.exit(1); }
process.exit(result.status === null ? 1 : result.status);
