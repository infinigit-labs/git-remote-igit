'use strict';

const targets = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'win32-x64': 'x86_64-pc-windows-msvc'
};

function targetFor(platform = process.platform, arch = process.arch) {
  const target = targets[`${platform}-${arch}`];
  if (!target) throw new Error(`Unsupported platform: ${platform}-${arch}`);
  return target;
}

module.exports = { targetFor };
