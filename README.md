# git-remote-igit

Git remote helper for InfiniGit's native `igit://` transport.

```bash
cargo install --path .
git clone igit://infinigit.com/username/repository
```

Git discovers the executable by its `git-remote-igit` name. The helper resolves
human-readable repository coordinates through the InfiniGit directory and
uses the external `infinigit-pack` bridge to synchronize canister packfiles.

This directory is an independent Cargo package with package-local unit and
transport tests, ready to be extracted into its own repository later.
