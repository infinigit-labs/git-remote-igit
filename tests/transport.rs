#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

const PRINCIPAL: &str = "aaaaa-aa";

fn git(cwd: &Path, data: &Path, args: &[&str]) -> Output {
    let helper = env!("CARGO_BIN_EXE_git-remote-igit");
    let helper_dir = Path::new(helper).parent().unwrap();
    let path = format!(
        "{}:{}",
        helper_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("PATH", path)
        .env("INFINIGIT_DATA_DIR", data)
        .env("INFINIGIT_PRINCIPAL", PRINCIPAL)
        // This test process explicitly trusts the installed InfiniGit helper;
        // Git otherwise blocks custom protocols in recursive submodule clones.
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "protocol.igit.allow")
        .env("GIT_CONFIG_VALUE_0", "always")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn configure(repo: &Path, data: &Path) {
    git(repo, data, &["config", "user.name", "InfiniGit Test"]);
    git(
        repo,
        data,
        &["config", "user.email", "infinigit@example.test"],
    );
}

#[test]
fn standard_clone_push_fetch_pull_branch_tag_force_and_delete_work() {
    let temp = TempDir::new().unwrap();
    let data = temp.path().join("data");
    let bare = data.join(PRINCIPAL).join("demo.git");
    fs::create_dir_all(bare.parent().unwrap()).unwrap();
    git(
        temp.path(),
        &data,
        &["init", "--bare", bare.to_str().unwrap()],
    );

    let library_bare = data.join(PRINCIPAL).join("library.git");
    git(
        temp.path(),
        &data,
        &["init", "--bare", library_bare.to_str().unwrap()],
    );
    let library_source = temp.path().join("library-source");
    fs::create_dir(&library_source).unwrap();
    git(&library_source, &data, &["init", "-b", "main"]);
    configure(&library_source, &data);
    fs::write(library_source.join("library.txt"), "nested repository\n").unwrap();
    git(&library_source, &data, &["add", "."]);
    git(&library_source, &data, &["commit", "-m", "library"]);
    git(
        &library_source,
        &data,
        &["remote", "add", "origin", "igit://aaaaa-aa/library"],
    );
    git(&library_source, &data, &["push", "-u", "origin", "main"]);

    let source = temp.path().join("source");
    fs::create_dir(&source).unwrap();
    git(&source, &data, &["init", "-b", "main"]);
    configure(&source, &data);
    fs::write(source.join("README.md"), "one\n").unwrap();
    git(
        &source,
        &data,
        &[
            "-c",
            "protocol.igit.allow=always",
            "submodule",
            "add",
            "-b",
            "main",
            "igit://aaaaa-aa/library",
            "vendor/library",
        ],
    );
    git(&source, &data, &["add", "."]);
    let submodule_commit =
        String::from_utf8(git(&library_source, &data, &["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
    git(&source, &data, &["commit", "-m", "first"]);
    git(
        &source,
        &data,
        &["remote", "add", "origin", "igit://aaaaa-aa/demo"],
    );
    git(&source, &data, &["push", "-u", "origin", "main"]);

    let clone = temp.path().join("clone");
    git(
        temp.path(),
        &data,
        &[
            "clone",
            "-c",
            "protocol.igit.allow=always",
            "--recurse-submodules",
            "-b",
            "main",
            "igit://aaaaa-aa/demo",
            clone.to_str().unwrap(),
        ],
    );
    configure(&clone, &data);
    assert_eq!(
        fs::read_to_string(clone.join("README.md")).unwrap(),
        "one\n"
    );
    let submodule = git(&clone, &data, &["ls-tree", "HEAD", "vendor/library"]);
    assert_eq!(
        String::from_utf8(submodule.stdout).unwrap().trim(),
        format!("160000 commit {submodule_commit}\tvendor/library")
    );
    assert_eq!(
        fs::read_to_string(clone.join("vendor/library/library.txt")).unwrap(),
        "nested repository\n"
    );

    git(&source, &data, &["checkout", "-b", "feature"]);
    fs::write(source.join("feature.txt"), "branch\n").unwrap();
    git(&source, &data, &["add", "."]);
    git(&source, &data, &["commit", "-m", "feature"]);
    git(&source, &data, &["tag", "v1"]);
    git(&source, &data, &["push", "origin", "feature", "v1"]);
    git(&clone, &data, &["fetch", "--tags", "origin"]);
    assert!(clone.join(".git/refs/tags/v1").exists());

    git(&source, &data, &["checkout", "main"]);
    fs::write(source.join("README.md"), "two\n").unwrap();
    git(&source, &data, &["commit", "-am", "second"]);
    git(&source, &data, &["push", "origin", "main"]);
    git(&clone, &data, &["pull", "--ff-only"]);
    assert_eq!(
        fs::read_to_string(clone.join("README.md")).unwrap(),
        "two\n"
    );

    git(
        &source,
        &data,
        &["push", "origin", ":feature", ":refs/tags/v1"],
    );
    let refs = git(
        temp.path(),
        &data,
        &["--git-dir", bare.to_str().unwrap(), "show-ref"],
    );
    let refs = String::from_utf8(refs.stdout).unwrap();
    assert!(!refs.contains("feature"));
    assert!(!refs.contains("refs/tags/v1"));
}

#[test]
fn public_repository_allows_outsider_clone_but_private_repo_is_hidden() {
    let temp = TempDir::new().unwrap();
    let data = temp.path().join("data");
    let bare = data.join(PRINCIPAL).join("public.git");
    fs::create_dir_all(bare.parent().unwrap()).unwrap();
    git(
        temp.path(),
        &data,
        &["init", "--bare", bare.to_str().unwrap()],
    );
    git(
        temp.path(),
        &data,
        &[
            "--git-dir",
            bare.to_str().unwrap(),
            "config",
            "infinigit.public",
            "true",
        ],
    );

    let helper = env!("CARGO_BIN_EXE_git-remote-igit");
    let helper_dir = Path::new(helper).parent().unwrap();
    let path = format!(
        "{}:{}",
        helper_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let public = Command::new("git")
        .args(["ls-remote", "igit://aaaaa-aa/public"])
        .current_dir(temp.path())
        .env("PATH", &path)
        .env("INFINIGIT_DATA_DIR", &data)
        .env("INFINIGIT_PRINCIPAL", "rrkah-fqaaa-aaaaa-aaaaq-cai")
        .output()
        .unwrap();
    assert!(
        public.status.success(),
        "{}",
        String::from_utf8_lossy(&public.stderr)
    );

    let private_bare = data.join(PRINCIPAL).join("private.git");
    git(
        temp.path(),
        &data,
        &["init", "--bare", private_bare.to_str().unwrap()],
    );
    let private = Command::new("git")
        .args(["ls-remote", "igit://aaaaa-aa/private"])
        .current_dir(temp.path())
        .env("PATH", path)
        .env("INFINIGIT_DATA_DIR", data)
        .env("INFINIGIT_PRINCIPAL", "rrkah-fqaaa-aaaaa-aaaaq-cai")
        .output()
        .unwrap();
    assert!(!private.status.success());
    assert!(String::from_utf8_lossy(&private.stderr).contains("repository not found"));
}

#[test]
fn username_clone_resolves_and_materializes_without_a_project_manifest() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("source.git");
    let cache = temp.path().join("cache");
    let outside = temp.path().join("outside");
    let clone = outside.join("demo");
    fs::create_dir(&outside).unwrap();
    // macOS exposes temporary directories through /var, while a child shell's
    // physical working directory resolves that symlink to /private/var.
    let canonical_outside = outside.canonicalize().unwrap();
    let initialized = Command::new("git")
        .args(["init", "--bare", source.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(initialized.status.success());

    let mock_icp = temp.path().join("icp");
    let icp_log = temp.path().join("icp.log");
    fs::write(&mock_icp, "#!/usr/bin/env bash\nset -e\nprintf '%s\\n' \"$*\" >\"$INFINIGIT_TEST_ICP_LOG\"\nprintf '%s\\n' 'variant { ok = record { owner = principal \"aaaaa-aa\"; shard = principal \"rrkah-fqaaa-aaaaa-aaaaq-cai\"; storage_id = \"igit-r-1\"; visibility = variant { Public } } }'\n").unwrap();
    let mock_pack = temp.path().join("infinigit-pack");
    fs::write(&mock_pack, "#!/usr/bin/env bash\nset -e\ntest \"$1\" = materialize\ntest \"$4\" = igit-r-1\ntest \"$PWD\" = \"$INFINIGIT_EXPECTED_WORKING_DIRECTORY\"\ntest -z \"${INFINIGIT_PROJECT_ROOT:-}\"\ntest \"$INFINIGIT_NETWORK\" = 'http://127.0.0.1:4943'\ntest \"$INFINIGIT_ROOT_KEY\" = fetch\ntest \"$INFINIGIT_IDENTITY\" = infinigit-browser\nmkdir -p \"$(dirname \"$5\")\"\ncp -R \"$INFINIGIT_TEST_SOURCE\" \"$5\"\n").unwrap();
    fs::set_permissions(&mock_icp, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&mock_pack, fs::Permissions::from_mode(0o755)).unwrap();

    let helper = env!("CARGO_BIN_EXE_git-remote-igit");
    let path = format!(
        "{}:{}",
        Path::new(helper).parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("git")
        .args([
            "clone",
            "igit://localhost/alice-dev/demo",
            clone.to_str().unwrap(),
        ])
        .current_dir(&outside)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("PATH", path)
        .env("INFINIGIT_DIRECTORY_CANISTER_ID", "directory-id")
        .env("INFINIGIT_NETWORK", "http://127.0.0.1:4943")
        .env("INFINIGIT_ROOT_KEY", "fetch")
        .env("INFINIGIT_IDENTITY", "infinigit-browser")
        .env("INFINIGIT_EXPECTED_WORKING_DIRECTORY", &canonical_outside)
        .env("INFINIGIT_ICP_BIN", &mock_icp)
        .env("INFINIGIT_TEST_ICP_LOG", &icp_log)
        .env("INFINIGIT_PACK_BIN", &mock_pack)
        .env("INFINIGIT_DATA_DIR", &cache)
        .env("INFINIGIT_TEST_SOURCE", &source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(clone.join(".git").is_dir());
    assert!(cache.join("alice-dev/demo.git/HEAD").is_file());
    let icp_call = fs::read_to_string(icp_log).unwrap();
    assert!(icp_call.contains("--network http://127.0.0.1:4943"));
    assert!(icp_call.contains("--root-key fetch"));
    assert!(icp_call.contains("--identity infinigit-browser"));
}

#[test]
fn production_clone_ignores_stale_local_configuration() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("source.git");
    let clone = temp.path().join("clone");
    let initialized = Command::new("git")
        .args(["init", "--bare", source.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(initialized.status.success());

    let mock_icp = temp.path().join("icp");
    let mock_pack = temp.path().join("infinigit-pack");
    fs::write(
        &mock_icp,
        "#!/usr/bin/env bash\nset -e\ntest \"$3\" = 'vc3gg-2qaaa-aaaae-qklda-cai'\n[[ \"$*\" == *\"--identity-password-file $INFINIGIT_TEST_PASSWORD_FILE\"* ]]\ntest \"${*: -2:1}\" = '--network'\ntest \"${*: -1}\" = 'ic'\nprintf '%s\\n' 'interactive identity prompt' >&2\nprintf '%s\\n' 'variant { ok = record { owner = principal \"aaaaa-aa\"; shard = principal \"rrkah-fqaaa-aaaaa-aaaaq-cai\"; storage_id = \"igit-production-1\"; visibility = variant { Public } } }'\n",
    )
    .unwrap();
    fs::write(
        &mock_pack,
        "#!/usr/bin/env bash\nset -e\ntest \"$1\" = materialize\ntest \"$4\" = igit-production-1\ntest \"$INFINIGIT_NETWORK\" = ic\ntest \"$INFINIGIT_IDENTITY_PASSWORD_FILE\" = \"$INFINIGIT_TEST_PASSWORD_FILE\"\ntest -z \"${INFINIGIT_ROOT_KEY:-}\"\nmkdir -p \"$(dirname \"$5\")\"\ncp -R \"$INFINIGIT_TEST_SOURCE\" \"$5\"\n",
    )
    .unwrap();
    fs::set_permissions(&mock_icp, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&mock_pack, fs::Permissions::from_mode(0o755)).unwrap();

    let stale = temp.path().join("stale.gitconfig");
    let password_file = temp.path().join("identity-password");
    fs::write(&password_file, "secret\n").unwrap();
    fs::write(
        &stale,
        "[infinigit]\n\thost = localhost\n\tdirectory-canister = local-directory\n\tnetwork = http://127.0.0.1:4943\n\troot-key = fetch\n\tpack-bin = /missing/local/infinigit-pack\n",
    )
    .unwrap();
    let helper = env!("CARGO_BIN_EXE_git-remote-igit");
    let path = format!(
        "{}:{}",
        Path::new(helper).parent().unwrap().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("git")
        .args([
            "clone",
            "igit://infinigit.com/infinigit/first-repo-ever",
            clone.to_str().unwrap(),
        ])
        .current_dir(temp.path())
        .env("GIT_CONFIG_GLOBAL", stale)
        .env("PATH", path)
        .env("INFINIGIT_ICP_BIN", mock_icp)
        .env("INFINIGIT_PACK_BIN", mock_pack)
        .env("INFINIGIT_ROOT_KEY", "fetch")
        .env("INFINIGIT_DATA_DIR", temp.path().join("cache"))
        .env("INFINIGIT_TEST_SOURCE", source)
        .env("INFINIGIT_TEST_PASSWORD_FILE", &password_file)
        .env("INFINIGIT_IDENTITY_PASSWORD_FILE", &password_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(clone.join(".git").is_dir());
    assert!(String::from_utf8_lossy(&output.stderr).contains("interactive identity prompt"));
}
