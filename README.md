# git-remote-igit

Git remote helper for infinigit's native `igit://` transport.

```bash
cargo install git-remote-igit
# or: npm install --global git-remote-igit
git clone igit://infinigit.com/username/repository
```

Git discovers the executable by its `git-remote-igit` name. The helper resolves
human-readable repository coordinates through the infinigit directory and
uses the bundled `infinigit-pack` bridge to synchronize canister packfiles.
`infinigit.com` automatically selects the ICP mainnet and production directory;
no environment variables or Git configuration are required for public clones.
Explicit configuration remains available for local development and other
infinigit installations.

The helper automatically negotiates transport capabilities with each storage
shard. New shards use batched resumable pack uploads, multi-chunk downloads,
changed-ref object negotiation, incremental packs, immutable local pack-index
caching, and bounded adaptive concurrency. If a shard predates those APIs, the
same binary falls back to the original endpoints without changing Git
semantics. Set `INFINIGIT_DISABLE_TRANSPORT_V2=1` to force that compatibility
path, or `INFINIGIT_TRANSPORT_TIMINGS=1` to print phase-level timings.

## Releases

See [PUBLISHING.md](PUBLISHING.md) for registry setup, versioning, publishing,
verification, and partial-release recovery.

Tags named `v<version>` publish the crate and npm package and attach native
Linux, macOS, and Windows binaries to a GitHub Release. Keep the versions in
`Cargo.toml` and `package.json` identical before tagging. The `release`
environment needs a `CARGO_REGISTRY_TOKEN` secret. npm trusted publishing should
authorize `infinigit-labs/git-remote-igit` and `.github/workflows/release.yml`;
an `NPM_TOKEN` secret can bootstrap the first publication.
