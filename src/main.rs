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
use tempfile::NamedTempFile;

const PRODUCTION_HOST: &str = "infinigit.com";
const PRODUCTION_DIRECTORY: &str = "vc3gg-2qaaa-aaaae-qklda-cai";
const PRODUCTION_NETWORK: &str = "ic";

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("infinigit: {}", message.as_ref());
    std::process::exit(1)
}

fn valid_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

fn parse_remote(url: &str) -> Result<(Option<&str>, &str, &str), String> {
    let value = url
        .strip_prefix("igit://")
        .or_else(|| url.strip_prefix("igit::"))
        .ok_or_else(|| "remote must use igit://<host>/<username>/<repository>".to_string())?;
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

fn password_backed_identity(icp: &str, selected: Option<&str>) -> bool {
    let output = match Command::new(icp).args(["identity", "list", "--json"]).output() {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };
    let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => return false,
    };
    password_backed_identity_json(&value, selected)
}

fn password_backed_identity_json(value: &serde_json::Value, selected: Option<&str>) -> bool {
    let name = selected.or_else(|| value.get("default_identity")?.as_str());
    value
        .get("identities")
        .and_then(serde_json::Value::as_array)
        .and_then(|identities| identities.iter().find(|entry| entry.get("name").and_then(serde_json::Value::as_str) == name))
        .and_then(|entry| entry.get("format"))
        .and_then(serde_json::Value::as_str)
        == Some("password")
}

fn unlock_identity(icp: &str, identity: Option<&str>) -> Option<NamedTempFile> {
    if !password_backed_identity(icp, identity) {
        return None;
    }
    let password = rpassword::prompt_password("Enter identity password: ")
        .unwrap_or_else(|error| fail(format!("failed to read identity password: {error}")));
    let mut file = NamedTempFile::new()
        .unwrap_or_else(|error| fail(format!("cannot create identity password file: {error}")));
    writeln!(file, "{password}")
        .unwrap_or_else(|error| fail(format!("cannot write identity password file: {error}")));
    Some(file)
}

fn validate_host(host: Option<&str>, configured_host: Option<&str>) -> Result<(), String> {
    match (host, configured_host) {
        (Some(PRODUCTION_HOST), _) => Ok(()),
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

fn candid_text_field(response: &str, field: &str) -> Option<String> {
    let marker = format!("{field} = \"");
    response
        .split(&marker)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .filter(|value| valid_atom(value))
        .map(str::to_owned)
}

fn resolve_repository(
    namespace: &str,
    repository: &str,
    directory: &str,
    production: bool,
    password_file: Option<&Path>,
) -> (String, String, String) {
    let icp = configured("INFINIGIT_ICP_BIN", "infinigit.icp-bin").unwrap_or_else(|| "icp".into());
    let argument = format!("(\"{namespace}\", \"{repository}\")");
    let mut command = Command::new(icp);
    command.args([
        "canister",
        "call",
        directory,
        "resolve_repository",
        &argument,
    ]);
    if let Some(identity) = configured("INFINIGIT_IDENTITY", "infinigit.identity") {
        command.args(["--identity", &identity]);
    }
    if let Some(path) = password_file {
        command.arg("--identity-password-file").arg(path);
    }
    if production {
        command.args(["--network", PRODUCTION_NETWORK]);
    } else if let Some(network) = configured("INFINIGIT_NETWORK", "infinigit.network") {
        command.args(["--network", &network]);
        if let Some(root_key) = configured("INFINIGIT_ROOT_KEY", "infinigit.root-key") {
            command.args(["--root-key", &root_key]);
        }
    } else if let Some(project_root) =
        configured("INFINIGIT_PROJECT_ROOT", "infinigit.project-root")
    {
        command.args(["--project-root-override", &project_root]);
    }
    let output = command
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
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
    let storage_id = candid_text_field(&response, "storage_id")
        .unwrap_or_else(|| fail("invalid directory storage ID"));
    (owner, shard, storage_id)
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

fn pack_bridge(production: bool) -> PathBuf {
    env::var_os("INFINIGIT_PACK_BIN")
        .map(PathBuf::from)
        .or_else(|| {
            (!production)
                .then(|| git_config("infinigit.pack-bin"))
                .flatten()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            env::current_exe()
                .unwrap_or_else(|e| fail(e.to_string()))
                .with_file_name("infinigit-pack")
        })
}

fn run_pack(
    action: &str,
    canister: &str,
    owner: &str,
    repository: &str,
    repo: &Path,
    project_root: Option<&Path>,
    production: bool,
    password_file: Option<&Path>,
) -> bool {
    let mut command = Command::new(pack_bridge(production));
    command
        .args([action, canister, owner, repository])
        .arg(repo);
    if let Some(root) = project_root {
        command
            .current_dir(root)
            .env("INFINIGIT_PROJECT_ROOT", root);
    }
    if let Some(icp) = configured("INFINIGIT_ICP_BIN", "infinigit.icp-bin") {
        command.env("INFINIGIT_ICP_BIN", icp);
    }
    if production {
        command.env("INFINIGIT_NETWORK", PRODUCTION_NETWORK);
        command.env_remove("INFINIGIT_ROOT_KEY");
    } else if let Some(network) = configured("INFINIGIT_NETWORK", "infinigit.network") {
        command.env("INFINIGIT_NETWORK", network);
        if let Some(root_key) = configured("INFINIGIT_ROOT_KEY", "infinigit.root-key") {
            command.env("INFINIGIT_ROOT_KEY", root_key);
        }
    }
    if let Some(identity) = configured("INFINIGIT_IDENTITY", "infinigit.identity") {
        command.env("INFINIGIT_IDENTITY", identity);
    }
    if let Some(path) = password_file {
        command.env("INFINIGIT_IDENTITY_PASSWORD_FILE", path);
    }
    command
        .status()
        .unwrap_or_else(|e| fail(format!("cannot start pack bridge: {e}")))
        .success()
}

fn sync_from_canister(
    canister: &str,
    owner: &str,
    repository: &str,
    repo: &Path,
    project_root: Option<&Path>,
    production: bool,
    password_file: Option<&Path>,
) {
    if !run_pack(
        "materialize",
        canister,
        owner,
        repository,
        repo,
        project_root,
        production,
        password_file,
    ) {
        fail("repository not found")
    }
}

fn sync_to_canister(
    canister: &str,
    owner: &str,
    repository: &str,
    repo: &Path,
    project_root: Option<&Path>,
    production: bool,
    password_file: Option<&Path>,
) {
    if !run_pack(
        "upload",
        canister,
        owner,
        repository,
        repo,
        project_root,
        production,
        password_file,
    ) {
        fail("canister rejected push")
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        fail("usage: git-remote-igit <remote-name> <igit-url>");
    }
    let (host, namespace, repository) = parse_remote(&args[2]).unwrap_or_else(|e| fail(e));
    let production = host == Some(PRODUCTION_HOST);
    let configured_host = git_config("infinigit.host");
    validate_host(host, configured_host.as_deref()).unwrap_or_else(|e| fail(e));
    let direct_data = env::var_os("INFINIGIT_DATA_DIR").is_some();
    let directory = env::var("INFINIGIT_DIRECTORY_CANISTER_ID")
        .ok()
        .or_else(|| {
            production
                .then(|| PRODUCTION_DIRECTORY.to_owned())
                .or_else(|| {
                    (!direct_data)
                        .then(|| git_config("infinigit.directory-canister"))
                        .flatten()
                })
        });
    let direct_canister = env::var("INFINIGIT_CANISTER").ok();
    let icp = configured("INFINIGIT_ICP_BIN", "infinigit.icp-bin").unwrap_or_else(|| "icp".into());
    let identity = configured("INFINIGIT_IDENTITY", "infinigit.identity");
    let supplied_password_file = env::var_os("INFINIGIT_IDENTITY_PASSWORD_FILE").map(PathBuf::from);
    let temporary_password_file = supplied_password_file
        .is_none()
        .then(|| unlock_identity(&icp, identity.as_deref()))
        .flatten();
    let password_file = supplied_password_file
        .as_deref()
        .or_else(|| temporary_password_file.as_ref().map(|file| file.path()));
    let (owner, canister, storage_id) = if let Some(directory) = directory.as_deref() {
        let (owner, shard, storage_id) =
            resolve_repository(namespace, repository, directory, production, password_file);
        (owner, Some(shard), storage_id)
    } else {
        (namespace.to_owned(), direct_canister, repository.to_owned())
    };
    let caller = env::var("INFINIGIT_PRINCIPAL").ok();
    let project_root = (!production)
        .then(|| configured("INFINIGIT_PROJECT_ROOT", "infinigit.project-root"))
        .flatten()
        .map(PathBuf::from);
    let root = env::var_os("INFINIGIT_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            (!production)
                .then(|| git_config("infinigit.data-dir"))
                .flatten()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(".infinigit/repositories"));
    let repo = repository_path(&root, namespace, repository).unwrap_or_else(|e| fail(e));
    if let Some(canister) = canister.as_deref() {
        eprintln!(
            "infinigit: synchronizing {} via canister {}",
            repo.display(),
            canister
        );
        sync_from_canister(
            canister,
            &owner,
            &storage_id,
            &repo,
            project_root.as_deref(),
            production,
            password_file,
        );
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
                        sync_to_canister(
                            canister,
                            &owner,
                            &storage_id,
                            &repo,
                            project_root.as_deref(),
                            production,
                            password_file,
                        );
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
    fn detects_only_the_selected_password_backed_identity() {
        let identities = serde_json::json!({
            "default_identity": "secure",
            "identities": [
                { "name": "plain", "format": "plaintext" },
                { "name": "secure", "format": "password" }
            ]
        });
        assert!(password_backed_identity_json(&identities, None));
        assert!(password_backed_identity_json(&identities, Some("secure")));
        assert!(!password_backed_identity_json(&identities, Some("plain")));
        assert!(!password_backed_identity_json(&identities, Some("missing")));
    }

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
        let response = "owner = principal \"aaaaa-aa\"; shard = principal \"rrkah-fqaaa-aaaaa-aaaaq-cai\"; storage_id = \"igit-r-7\"";
        assert_eq!(
            candid_principal_field(response, "owner").as_deref(),
            Some("aaaaa-aa")
        );
        assert_eq!(
            candid_principal_field(response, "shard").as_deref(),
            Some("rrkah-fqaaa-aaaaa-aaaaq-cai")
        );
        assert_eq!(candid_principal_field(response, "missing"), None);
        assert_eq!(
            candid_text_field(response, "storage_id").as_deref(),
            Some("igit-r-7")
        );
        assert_eq!(
            candid_text_field("storage_id = \"bad/value\"", "storage_id"),
            None
        );
    }

    #[test]
    fn host_validation_accepts_configured_and_legacy_urls_but_rejects_other_installations() {
        assert!(validate_host(Some("localhost"), Some("localhost")).is_ok());
        assert!(validate_host(Some(PRODUCTION_HOST), Some("localhost")).is_ok());
        assert!(validate_host(None, Some("localhost")).is_ok());
        assert!(validate_host(Some("git.example"), None).is_ok());
        assert_eq!(
            validate_host(Some("other.example"), Some("git.example")),
            Err("unknown InfiniGit host: other.example".into())
        );
    }
}
