'use strict';

const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { spawnSync } = require('node:child_process');
const pkg = require('../../package.json');
const { targetFor } = require('./platform');

const binaries = ['git-remote-igit', 'infinigit-pack'];
const target = targetFor();
const extension = process.platform === 'win32' ? '.zip' : '.tar.gz';
const asset = `${pkg.name}-v${pkg.version}-${target}${extension}`;
const url = `https://github.com/infinigit-labs/${pkg.name}/releases/download/v${pkg.version}/${asset}`;
const vendor = path.join(__dirname, '..', 'vendor');

function request(source, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(source, { headers: { 'User-Agent': `${pkg.name}-npm/${pkg.version}` } }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location && redirects) {
        response.resume(); resolve(request(response.headers.location, redirects - 1));
      } else if (response.statusCode === 200) resolve(response);
      else { response.resume(); reject(new Error(`Download failed with HTTP ${response.statusCode}`)); }
    }).on('error', reject);
  });
}

async function install() {
  fs.mkdirSync(vendor, { recursive: true });
  const archive = path.join(vendor, asset);
  await pipeline(await request(url), fs.createWriteStream(archive));
  const result = spawnSync('tar', ['-xf', archive, '-C', vendor], { stdio: 'inherit' });
  fs.rmSync(archive, { force: true });
  if (result.status !== 0) throw new Error('Could not extract downloaded archive');
  if (process.platform !== 'win32') {
    for (const binary of binaries) fs.chmodSync(path.join(vendor, binary), 0o755);
  }
}

install().catch(error => { console.error(`${pkg.name}: ${error.message}`); process.exitCode = 1; });
