//! Git remote-helper gateway for local InfiniGit development.
//!
//! Git invokes this executable for `igit://<host>/<username>/<repo>` remotes.
//! It resolves the username through the directory canister, then hands the smart protocol to
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

fn parse_remote(url: &str) -> Result<(Option<&str>, &str, &str), String> {
    let value = url
        .strip_prefix("igit://")
        .or_else(|| url.strip_prefix("igit::"))
        .ok_or_else(|| "remote must use igit://<host>/<username>/<repository>".to_string())?;
    let valid_atom = |s: &str| {
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
            && !s.starts_with('.')
            && !s.ends_with('.')
    };
    let parts = value.split('/').collect::<Vec<_>>();
    let (host, namespace, repository) = match parts.as_slice() {
        [namespace, repository] => (None, *namespace, *repository),
        [host, namespace, repository] if valid_atom(host) => (Some(*host), *namespace, *repository),
        _ => return Err("remote must contain a host, username, and repository".into()),
    };
    if namespace == "2vxsx-fae" || !valid_atom(namespace) {
        return Err("a valid InfiniGit username is required".into());
    }
    if !valid_atom(repository) {
        return Err("invalid repository name".into());
    }
    Ok((host, namespace, repository))
}

fn git_config(key: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--global", "--get", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn configured(env_key: &str, git_key: &str) -> Option<String> {
    env::var(env_key).ok().or_else(|| git_config(git_key))
}

fn validate_host(host: Option<&str>, configured_host: Option<&str>) -> Result<(), String> {
    match (host, configured_host) {
        (Some(host), Some(configured)) if host != configured => {
            Err(format!("unknown InfiniGit host: {host}"))
        }
        _ => Ok(()),
    }
}

fn candid_principal_field(response: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = principal \"");
    response
        .split(&marker)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn resolve_repository(namespace: &str, repository: &str, directory: &str) -> (String, String) {
    let icp = configured("INFINIGIT_ICP_BIN", "infinigit.icp-bin").unwrap_or_else(|| "icp".into());
    let project_root = configured("INFINIGIT_PROJECT_ROOT", "infinigit.project-root")
        .unwrap_or_else(|| {
            fail("InfiniGit local project is not configured; run scripts/start-local.sh")
        });
    let argument = format!("(\"{namespace}\", \"{repository}\")");
    let output = Command::new(icp)
        .args([
            "canister",
            "call",
            directory,
            "resolve_repository",
            &argument,
            "--project-root-override",
            &project_root,
        ])
        .output()
        .unwrap_or_else(|e| fail(format!("cannot query the InfiniGit directory: {e}")));
    if !output.status.success() {
        fail("repository not found")
    }
    let response =
        String::from_utf8(output.stdout).unwrap_or_else(|_| fail("invalid directory response"));
    if response.contains("err =") {
        fail("repository not found")
    }
    let owner = candid_principal_field(&response, "owner")
        .unwrap_or_else(|| fail("invalid directory owner"));
    let shard = candid_principal_field(&response, "shard")
        .unwrap_or_else(|| fail("invalid directory shard"));
    (owner, shard)
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
        .or_else(|| git_config("infinigit.pack-bin").map(PathBuf::from))
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
    let (host, namespace, repository) = parse_remote(&args[2]).unwrap_or_else(|e| fail(e));
    let configured_host = git_config("infinigit.host");
    validate_host(host, configured_host.as_deref()).unwrap_or_else(|e| fail(e));
    let direct_data = env::var_os("INFINIGIT_DATA_DIR").is_some();
    let directory = env::var("INFINIGIT_DIRECTORY_CANISTER_ID")
        .ok()
        .or_else(|| {
            (!direct_data)
                .then(|| git_config("infinigit.directory-canister"))
                .flatten()
        });
    let direct_canister = env::var("INFINIGIT_CANISTER").ok();
    let (owner, canister) = if let Some(directory) = directory.as_deref() {
        let (owner, shard) = resolve_repository(namespace, repository, directory);
        (owner, Some(shard))
    } else {
        (namespace.to_owned(), direct_canister)
    };
    let caller = env::var("INFINIGIT_PRINCIPAL").ok();
    let root = env::var_os("INFINIGIT_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| git_config("infinigit.data-dir").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(".infinigit/repositories"));
    let repo = repository_path(&root, &owner, repository).unwrap_or_else(|e| fail(e));
    if let Some(canister) = canister.as_deref() {
        eprintln!(
            "infinigit: synchronizing {} via canister {}",
            repo.display(),
            canister
        );
        sync_from_canister(canister, &owner, repository, &repo);
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
    let owner_authenticated = caller.as_deref() == Some(owner.as_str());

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
                        sync_to_canister(canister, &owner, repository, &repo);
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
            (None, "aaaaa-aa", "demo")
        );
        assert_eq!(
            parse_remote("igit://localhost/alice/demo").unwrap(),
            (Some("localhost"), "alice", "demo")
        );
        assert!(parse_remote("https://aaaaa-aa/demo").is_err());
        assert!(parse_remote("igit://2vxsx-fae/demo").is_err());
        assert!(parse_remote("igit://aaaaa-aa/../escape").is_err());
        assert!(parse_remote("infinigit://aaaaa-aa/demo").is_err());
    }

    #[test]
    fn parses_directory_principals_and_rejects_missing_fields() {
        let response =
            "owner = principal \"aaaaa-aa\"; shard = principal \"rrkah-fqaaa-aaaaa-aaaaq-cai\"";
        assert_eq!(
            candid_principal_field(response, "owner").as_deref(),
            Some("aaaaa-aa")
        );
        assert_eq!(
            candid_principal_field(response, "shard").as_deref(),
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai")
        );
        assert_eq!(candid_principal_field(response, "missing"), None);
    }

    #[test]
    fn host_validation_accepts_configured_and_legacy_urls_but_rejects_other_installations() {
        assert!(validate_host(Some("localhost"), Some("localhost")).is_ok());
        assert!(validate_host(None, Some("localhost")).is_ok());
        assert!(validate_host(Some("git.example"), None).is_ok());
        assert_eq!(
            validate_host(Some("other.example"), Some("git.example")),
            Err("unknown InfiniGit host: other.example".into())
        );
    }
}
