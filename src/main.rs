//! Git remote-helper gateway for local InfiniGit development.
//!
//! Git invokes this executable for `igit://<principal>/<repo>` remotes.
//! It authenticates the caller principal, then hands the smart protocol to
//! Git's battle-tested upload-pack/receive-pack implementation. Production
//! deployments replace the local repository path with the ICP canister-backed
//! object gateway; the wire protocol seen by Git remains identical.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("infinigit: {}", message.as_ref());
    std::process::exit(1)
}

fn parse_remote(url: &str) -> Result<(&str, &str), String> {
    let value = url
        .strip_prefix("igit://")
        .or_else(|| url.strip_prefix("igit::"))
        .ok_or_else(|| "remote must use igit://<principal>/<repository>".to_string())?;
    let (principal, repository) = value
        .split_once('/')
        .ok_or_else(|| "remote must contain a principal and repository".to_string())?;
    let valid_atom = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
            && !s.starts_with('.')
            && !s.ends_with('.')
    };
    if principal == "2vxsx-fae" || !valid_atom(principal) {
        return Err("an authenticated, valid ICP principal is required".into());
    }
    if !valid_atom(repository) {
        return Err("invalid repository name".into());
    }
    Ok((principal, repository))
}

fn repository_path(root: &Path, principal: &str, repository: &str) -> Result<PathBuf, String> {
    if root
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("INFINIGIT_DATA_DIR cannot contain '..'".into());
    }
    Ok(root.join(principal).join(format!("{repository}.git")))
}

fn pack_bridge() -> PathBuf {
    env::var_os("INFINIGIT_PACK_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::current_exe()
                .unwrap_or_else(|e| fail(e.to_string()))
                .with_file_name("infinigit-pack")
        })
}

fn sync_from_canister(canister: &str, owner: &str, repository: &str, repo: &Path) {
    let status = Command::new(pack_bridge())
        .args(["materialize", canister, owner, repository])
        .arg(repo)
        .status()
        .unwrap_or_else(|e| fail(format!("cannot start pack materializer: {e}")));
    if !status.success() {
        fail("repository not found")
    }
}

fn sync_to_canister(canister: &str, owner: &str, repository: &str, repo: &Path) {
    let status = Command::new(pack_bridge())
        .args(["upload", canister, owner, repository])
        .arg(repo)
        .status()
        .unwrap_or_else(|e| fail(format!("cannot start pack uploader: {e}")));
    if !status.success() {
        fail("canister rejected push")
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        fail("usage: git-remote-igit <remote-name> <igit-url>");
    }
    let (owner, repository) = parse_remote(&args[2]).unwrap_or_else(|e| fail(e));
    let caller = env::var("INFINIGIT_PRINCIPAL").ok();
    let root = env::var_os("INFINIGIT_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".infinigit/repositories"));
    let repo = repository_path(&root, owner, repository).unwrap_or_else(|e| fail(e));
    let canister = env::var("INFINIGIT_CANISTER").ok();
    if let Some(canister) = canister.as_deref() {
        eprintln!(
            "infinigit: synchronizing {} via canister {}",
            repo.display(),
            canister
        );
        sync_from_canister(canister, owner, repository, &repo);
    }
    if !repo.join("HEAD").is_file() {
        fail(format!("repository does not exist: {}", repo.display()));
    }
    let public = Command::new("git")
        .args([
            "--git-dir",
            repo.to_str().unwrap(),
            "config",
            "--bool",
            "infinigit.public",
        ])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
        })
        .unwrap_or(false);
    let owner_authenticated = caller.as_deref() == Some(owner);

    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(line)) = lines.next() {
        match line.as_str() {
            "capabilities" => {
                println!("connect");
                println!();
            }
            "connect git-upload-pack" | "connect git-receive-pack" => {
                let reading = line == "connect git-upload-pack";
                if canister.is_none() && !(owner_authenticated || (reading && public)) {
                    fail("repository not found");
                }
                println!();
                io::stdout().flush().unwrap_or_else(|e| fail(e.to_string()));
                let service = line.strip_prefix("connect ").unwrap();
                let status = Command::new(service)
                    .arg(&repo)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()
                    .unwrap_or_else(|e| fail(format!("cannot start {service}: {e}")));
                if status.success() && !reading {
                    if let Some(canister) = canister.as_deref() {
                        sync_to_canister(canister, owner, repository, &repo);
                    }
                }
                std::process::exit(status.code().unwrap_or(1));
            }
            "" => return,
            other => fail(format!("unsupported remote-helper command: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_urls_and_rejects_anonymous_identity() {
        assert_eq!(
            parse_remote("igit://aaaaa-aa/demo").unwrap(),
            ("aaaaa-aa", "demo")
        );
        assert!(parse_remote("https://aaaaa-aa/demo").is_err());
        assert!(parse_remote("igit://2vxsx-fae/demo").is_err());
        assert!(parse_remote("igit://aaaaa-aa/../escape").is_err());
        assert!(parse_remote("infinigit://aaaaa-aa/demo").is_err());
    }
}
