'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { targetFor } = require('../lib/platform');

test('maps supported npm platforms to release targets', () => {
  assert.equal(targetFor('linux', 'x64'), 'x86_64-unknown-linux-gnu');
  assert.equal(targetFor('linux', 'arm64'), 'aarch64-unknown-linux-gnu');
  assert.equal(targetFor('darwin', 'arm64'), 'aarch64-apple-darwin');
  assert.equal(targetFor('win32', 'x64'), 'x86_64-pc-windows-msvc');
});

test('rejects unsupported platforms', () => {
  assert.throws(() => targetFor('aix', 'ppc64'), /Unsupported platform/);
});
