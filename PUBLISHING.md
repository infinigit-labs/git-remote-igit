# Publishing git-remote-igit

Releases publish the same version through three channels:

- the `git-remote-igit` crate on crates.io;
- the `git-remote-igit` package on npm;
- native binaries attached to a GitHub Release.

The release workflow runs when a `v<version>` tag is pushed. The tag, the
`Cargo.toml` version, and the `package.json` version must match exactly.

## One-time registry setup

Create a protected GitHub environment named `release` in
`infinigit-labs/git-remote-igit`. Restrict deployment to version tags and add
reviewers if releases should require approval.

For crates.io:

1. Sign in to crates.io with the GitHub account that will own the crate and
   verify its email address.
2. Create a crates.io API token scoped to publishing `git-remote-igit`.
3. Add it to the GitHub `release` environment as the
   `CARGO_REGISTRY_TOKEN` secret.

For npm, the first publication must establish ownership before trusted
publishing can be configured:

1. Confirm that the `git-remote-igit` package name is available and that the
   npm account or organization intended to own it is selected.
2. Create a granular npm automation token with permission to publish the
   package and add it temporarily as the `NPM_TOKEN` secret in the GitHub
   `release` environment.
3. Publish the first version with the workflow described below.
4. In the package settings on npmjs.com, add a GitHub Actions trusted publisher
   for organization `infinigit-labs`, repository `git-remote-igit`, workflow
   `release.yml`, and environment `release`.
5. Remove the `NPM_TOKEN` secret after a trusted-publisher release succeeds.

The workflow uses a GitHub-hosted runner and `id-token: write`, so npm can use
short-lived OIDC credentials. npm provenance is generated only when both the
GitHub repository and npm package are public.

## Publish a release

Start from a clean, current `main` branch:

```bash
git switch main
git pull --ff-only
cargo test --all-targets --locked
npm run test:npm
```

Update both package versions to the same value. Refresh the lockfile if Cargo
changes it, review the package contents, and commit the release:

```bash
cargo package --locked
npm pack --dry-run
git add Cargo.toml Cargo.lock package.json
git commit -m "Release v0.2.0"
git push origin main
```

Create and push an annotated tag only after `main` CI passes:

```bash
git tag -a v0.2.0 -m "git-remote-igit v0.2.0"
git push origin v0.2.0
```

The workflow verifies the versions and tests, builds Linux, macOS, and Windows
binaries, creates the GitHub Release, publishes crates.io, and then publishes
npm. Do not reuse or move a release tag after pushing it.

## Verify and recover

Verify all three channels after the workflow completes:

```bash
cargo info git-remote-igit
npm view git-remote-igit version
gh release view v0.2.0 --repo infinigit-labs/git-remote-igit
```

Registry versions are immutable. If only part of a release succeeds, do not
delete or overwrite the published version. Fix the failed job and rerun it when
safe; if a registry requires a new version, increment both manifests, commit,
and publish a new tag. Never expose registry tokens in logs or command history.
