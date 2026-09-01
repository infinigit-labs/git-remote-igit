# git-remote-igit

Git remote helper for InfiniGit's native `igit://` transport.

```bash
cargo install git-remote-igit
# or: npm install --global git-remote-igit
git clone igit://infinigit.com/username/repository
```

Git discovers the executable by its `git-remote-igit` name. The helper resolves
human-readable repository coordinates through the InfiniGit directory and
uses the external `infinigit-pack` bridge to synchronize canister packfiles.

## Releases

Tags named `v<version>` publish the crate and npm package and attach native
Linux, macOS, and Windows binaries to a GitHub Release. Keep the versions in
`Cargo.toml` and `package.json` identical before tagging. The `release`
environment needs a `CARGO_REGISTRY_TOKEN` secret. npm trusted publishing should
authorize `infinigit-labs/git-remote-igit` and `.github/workflows/release.yml`;
an `NPM_TOKEN` secret can bootstrap the first publication.
