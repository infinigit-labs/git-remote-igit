use candid_parser::candid::{
    IDLArgs,
    types::{Label, value::IDLValue},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const CHUNK_SIZE: usize = 512 * 1024;
const INLINE_OBJECT_LIMIT: usize = 128 * 1024;
static ARGUMENT_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("infinigit-pack: {}", message.as_ref());
    std::process::exit(1)
}

fn run(command: &mut Command) -> Output {
    let debug = format!("{command:?}");
    let output = command
        .output()
        .unwrap_or_else(|e| fail(format!("cannot run {debug}: {e}")));
    if !output.status.success() {
        fail(String::from_utf8_lossy(&output.stderr));
    }
    output
}

fn icp_json(canister: &str, method: &str, argument: &str) -> Value {
    let sequence = ARGUMENT_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "infinigit-candid-{}-{sequence}.did",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| fail(e.to_string()));
    file.write_all(argument.as_bytes())
        .unwrap_or_else(|e| fail(e.to_string()));
    drop(file);
    let mut command =
        Command::new(env::var_os("INFINIGIT_ICP_BIN").unwrap_or_else(|| "icp".into()));
    command
        .args(["canister", "call", canister, method, "--args-file"])
        .arg(&path)
        .arg("--json");
    if let Some(candid) = env::var_os("INFINIGIT_SHARD_CANDID") {
        command.arg("--candid").arg(candid);
    }
    if let Some(identity) = env::var_os("INFINIGIT_IDENTITY") {
        command.arg("--identity").arg(identity);
    }
    if let Some(network) = env::var_os("INFINIGIT_NETWORK") {
        command.arg("--network").arg(network);
        if let Some(root_key) = env::var_os("INFINIGIT_ROOT_KEY") {
            command.arg("--root-key").arg(root_key);
        }
    } else if let Some(root) = env::var_os("INFINIGIT_PROJECT_ROOT") {
        command.arg("--project-root-override").arg(root);
    }
    let output = command.output().unwrap_or_else(|e| fail(e.to_string()));
    let _ = fs::remove_file(&path);
    if !output.status.success() {
        fail(String::from_utf8_lossy(&output.stderr));
    }
    let envelope: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| fail(format!("invalid icp-cli JSON: {e}")));
    let candid = envelope
        .get("response_candid")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail(format!("icp-cli returned no Candid response: {envelope}")));
    let args: IDLArgs = candid_parser::parse_idl_args(candid)
        .unwrap_or_else(|e| fail(format!("invalid Candid response: {e}")));
    args.args
        .into_iter()
        .next()
        .map(idl_json)
        .unwrap_or(Value::Null)
}

fn label_text(label: Label) -> String {
    match label {
        Label::Named(name) => name,
        Label::Id(id) | Label::Unnamed(id) => id.to_string(),
    }
}

fn idl_json(value: IDLValue) -> Value {
    match value {
        IDLValue::Bool(value) => Value::Bool(value),
        IDLValue::Null | IDLValue::None | IDLValue::Reserved => Value::Null,
        IDLValue::Text(value) | IDLValue::Number(value) => Value::String(value),
        IDLValue::Float64(value) => serde_json::Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        IDLValue::Float32(value) => serde_json::Number::from_f64(value.into())
            .map(Value::Number)
            .unwrap_or(Value::Null),
        IDLValue::Opt(value) => idl_json(*value),
        IDLValue::Vec(values) => Value::Array(values.into_iter().map(idl_json).collect()),
        IDLValue::Blob(values) => Value::Array(
            values
                .into_iter()
                .map(|value| Value::Number(value.into()))
                .collect(),
        ),
        IDLValue::Record(fields) => Value::Object(
            fields
                .into_iter()
                .map(|field| (label_text(field.id), idl_json(field.val)))
                .collect(),
        ),
        IDLValue::Variant(value) => {
            let field = *value.0;
            Value::Object(
                [(label_text(field.id), idl_json(field.val))]
                    .into_iter()
                    .collect(),
            )
        }
        IDLValue::Principal(value) | IDLValue::Service(value) => Value::String(value.to_text()),
        IDLValue::Func(principal, method) => {
            Value::String(format!("{}:{method}", principal.to_text()))
        }
        IDLValue::Int(value) => Value::String(value.to_string()),
        IDLValue::Nat(value) => Value::String(value.to_string()),
        IDLValue::Nat8(value) => Value::Number(value.into()),
        IDLValue::Nat16(value) => Value::String(value.to_string()),
        IDLValue::Nat32(value) => Value::String(value.to_string()),
        IDLValue::Nat64(value) => Value::String(value.to_string()),
        IDLValue::Int8(value) => Value::Number(value.into()),
        IDLValue::Int16(value) => Value::String(value.to_string()),
        IDLValue::Int32(value) => Value::String(value.to_string()),
        IDLValue::Int64(value) => Value::String(value.to_string()),
    }
}

fn candid_blob(bytes: &[u8]) -> String {
    let values = bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(";");
    format!("vec {{{values}}}")
}

fn should_inline_object(size: usize) -> bool {
    size <= INLINE_OBJECT_LIMIT
}

fn git(git_dir: &Path, args: &[&str]) -> Output {
    run(Command::new("git").arg("--git-dir").arg(git_dir).args(args))
}

fn pack_id(bytes: &[u8]) -> String {
    assert!(bytes.len() >= 20);
    bytes[bytes.len() - 20..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct PackObjectMetadata {
    oid: String,
    kind: String,
    size: u64,
}

fn pack_object_metadata(git_dir: &Path, index: &Path) -> Vec<PackObjectMetadata> {
    let output = git(git_dir, &["verify-pack", "-v", index.to_str().unwrap()]);
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let oid = *fields.first()?;
            let kind = *fields.get(1)?;
            let size = fields.get(2)?.parse::<u64>().ok()?;
            (oid.len() == 40
                && oid.bytes().all(|c| c.is_ascii_hexdigit())
                && matches!(kind, "blob" | "tree" | "commit" | "tag"))
            .then(|| PackObjectMetadata {
                oid: oid.to_owned(),
                kind: kind.to_owned(),
                size,
            })
        })
        .collect()
}

fn canister_refs(canister: &str, owner: &str, repo: &str) -> Vec<(String, String)> {
    let result = icp_json(
        canister,
        "list_refs",
        &format!("(principal \"{owner}\", \"{repo}\")"),
    );
    result
        .get("ok")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail(format!("ref listing rejected: {result}")))
        .iter()
        .map(|entry| {
            (
                entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned(),
                entry.get("oid").and_then(Value::as_str).unwrap().to_owned(),
            )
        })
        .collect()
}

fn local_refs(git_dir: &Path) -> Vec<(String, String)> {
    let refs = git(
        git_dir,
        &["for-each-ref", "--format=%(refname) %(objectname)"],
    );
    String::from_utf8_lossy(&refs.stdout)
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(name, oid)| (name.to_owned(), oid.to_owned()))
        .collect()
}

fn candid_refs(refs: &[(String, String)]) -> String {
    refs.iter()
        .map(|(name, oid)| format!("record {{ name = \"{name}\"; oid = \"{oid}\" }}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn upload(canister: &str, owner: &str, repo: &str, git_dir: &Path) {
    let expected_refs = canister_refs(canister, owner, repo);
    git(git_dir, &["repack", "-a", "-d"]);
    let pack_dir = git_dir.join("objects/pack");
    let mut packs: Vec<PathBuf> = fs::read_dir(&pack_dir)
        .unwrap_or_else(|e| fail(e.to_string()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "pack"))
        .collect();
    packs.sort();
    let mut desired_pack_ids = Vec::new();
    for path in packs {
        let bytes = fs::read(&path).unwrap_or_else(|e| fail(e.to_string()));
        let id = pack_id(&bytes);
        desired_pack_ids.push(id.clone());
        let begin = icp_json(
            canister,
            "begin_pack",
            &format!(
                "(principal \"{owner}\", \"{repo}\", \"{id}\", {}, {CHUNK_SIZE})",
                bytes.len()
            ),
        );
        let complete = begin
            .get("ok")
            .and_then(|v| v.get("complete"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !complete {
            for (index, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
                let digest = format!("{:x}", Sha256::digest(chunk));
                let argument = format!(
                    "(principal \"{owner}\", \"{repo}\", \"{id}\", {index}, \"{digest}\", {})",
                    candid_blob(chunk)
                );
                let result = icp_json(canister, "put_pack_chunk", &argument);
                if result.get("ok").is_none() {
                    fail(format!("chunk upload rejected: {result}"));
                }
            }
            let result = icp_json(
                canister,
                "finalize_pack",
                &format!("(principal \"{owner}\", \"{repo}\", \"{id}\")"),
            );
            if result.get("ok").is_none() {
                fail(format!("pack finalization rejected: {result}"));
            }
        }
        let index = path.with_extension("idx");
        let objects = pack_object_metadata(git_dir, &index);
        let candid_objects = objects
            .iter()
            .map(|object| {
                format!(
                    "record {{ oid = \"{}\"; kind = variant {{ \"{}\" }}; size = {} }}",
                    object.oid, object.kind, object.size
                )
            })
            .collect::<Vec<_>>()
            .join(";");
        let indexed = icp_json(
            canister,
            "index_pack_objects",
            &format!("(principal \"{owner}\", \"{repo}\", \"{id}\", vec {{{candid_objects}}})"),
        );
        if indexed.get("ok").is_none() {
            fail(format!("pack index rejected: {indexed}"));
        }
    }

    // Browser repository views read canonical loose objects through get_object.
    // Publish those objects before moving refs so a newly visible commit can
    // never point at a tree/blob that the browser cannot load.
    index_browse_objects(canister, owner, repo, git_dir);

    let desired_refs = local_refs(git_dir);
    let result = icp_json(
        canister,
        "replace_refs_atomic",
        &format!(
            "(principal \"{owner}\", \"{repo}\", vec {{{}}}, vec {{{}}})",
            candid_refs(&expected_refs),
            candid_refs(&desired_refs)
        ),
    );
    if result.get("ok").is_none() {
        fail(format!("atomic ref publication rejected: {result}"));
    }
    let keep = desired_pack_ids
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(";");
    let pruned = icp_json(
        canister,
        "prune_packs",
        &format!("(principal \"{owner}\", \"{repo}\", vec {{{keep}}})"),
    );
    if pruned.get("ok").is_none() {
        fail(format!("obsolete pack pruning rejected: {pruned}"));
    }
}

fn materialize(canister: &str, owner: &str, repo: &str, git_dir: &Path) {
    if !git_dir.join("HEAD").exists() {
        fs::create_dir_all(git_dir)
            .unwrap_or_else(|e| fail(format!("cannot create {}: {e}", git_dir.display())));
        run(Command::new("git").args(["init", "--bare", git_dir.to_str().unwrap()]));
    }
    let packs = icp_json(
        canister,
        "list_packs",
        &format!("(principal \"{owner}\", \"{repo}\")"),
    );
    let values = packs
        .get("ok")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail(format!("pack listing rejected: {packs}")));
    let pack_dir = git_dir.join("objects/pack");
    fs::create_dir_all(&pack_dir)
        .unwrap_or_else(|e| fail(format!("cannot create {}: {e}", pack_dir.display())));
    for pack in values {
        if !pack
            .get("complete")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let id = pack.get("pack_id").and_then(Value::as_str).unwrap();
        let count: usize = pack
            .get("chunk_count")
            .and_then(Value::as_str)
            .unwrap()
            .parse()
            .unwrap();
        let mut bytes = Vec::new();
        for index in 0..count {
            let chunk = icp_json(
                canister,
                "get_pack_chunk",
                &format!("(principal \"{owner}\", \"{repo}\", \"{id}\", {index})"),
            );
            let data = chunk
                .get("ok")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail(format!("chunk download rejected: {chunk}")));
            bytes.extend(data.iter().map(|value| value.as_u64().unwrap() as u8));
        }
        if pack_id(&bytes) != id {
            fail(format!("pack checksum mismatch: {id}"));
        }
        let path = pack_dir.join(format!("pack-{id}.pack"));
        let already_present = fs::read(&path).is_ok_and(|existing| existing == bytes);
        if !already_present {
            if path.exists() {
                fs::remove_file(&path)
                    .unwrap_or_else(|e| fail(format!("cannot replace {}: {e}", path.display())));
            }
            fs::write(&path, bytes)
                .unwrap_or_else(|e| fail(format!("cannot write {}: {e}", path.display())));
        }
        git(git_dir, &["index-pack", path.to_str().unwrap()]);
    }
    let refs = icp_json(
        canister,
        "list_refs",
        &format!("(principal \"{owner}\", \"{repo}\")"),
    );
    let remote_refs = refs
        .get("ok")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail(format!("ref listing rejected: {refs}")));
    let desired_names = remote_refs
        .iter()
        .filter_map(|value| value.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for (name, _) in local_refs(git_dir) {
        if !desired_names.contains(&name.as_str()) {
            git(git_dir, &["update-ref", "-d", &name]);
        }
    }
    let mut has_main = false;
    for value in remote_refs {
        let name = value.get("name").and_then(Value::as_str).unwrap();
        let oid = value.get("oid").and_then(Value::as_str).unwrap();
        has_main |= name == "refs/heads/main";
        git(git_dir, &["update-ref", name, oid]);
    }
    if has_main {
        git(git_dir, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    }
}

fn index_browse_objects(canister: &str, owner: &str, repo: &str, git_dir: &Path) {
    let listed = git(git_dir, &["rev-list", "--objects", "--all"]);
    let mut object_ids = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    object_ids.sort_unstable();
    object_ids.dedup();
    for oid in object_ids {
        let kind_output = git(git_dir, &["cat-file", "-t", &oid]);
        let kind = String::from_utf8_lossy(&kind_output.stdout)
            .trim()
            .to_owned();
        if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
            fail(format!("unsupported browse object type: {kind}"));
        }
        let payload = git(git_dir, &["cat-file", &kind, &oid]).stdout;
        index_browse_object(canister, owner, repo, &oid, &kind, &payload);
    }
}

fn index_browse_object(
    canister: &str,
    owner: &str,
    repo: &str,
    oid: &str,
    kind: &str,
    payload: &[u8],
) {
    if should_inline_object(payload.len()) {
        let result = icp_json(
            canister,
            "put_object",
            &format!(
                "(principal \"{owner}\", \"{repo}\", \"{oid}\", variant {{ \"{kind}\" }}, {})",
                candid_blob(payload)
            ),
        );
        if result.get("ok").is_none() {
            fail(format!("browse object indexing rejected: {result}"));
        }
        return;
    }

    let begun = icp_json(
        canister,
        "begin_chunked_object",
        &format!(
            "(principal \"{owner}\", \"{repo}\", \"{oid}\", variant {{ \"{kind}\" }}, {}, {CHUNK_SIZE})",
            payload.len()
        ),
    );
    let complete = begun
        .get("ok")
        .and_then(|value| value.get("complete"))
        .and_then(Value::as_bool)
        .unwrap_or_else(|| fail(format!("chunked browse object rejected: {begun}")));
    if complete {
        return;
    }
    for (index, chunk) in payload.chunks(CHUNK_SIZE).enumerate() {
        let result = icp_json(
            canister,
            "put_object_chunk",
            &format!(
                "(principal \"{owner}\", \"{repo}\", \"{oid}\", {index}, {})",
                candid_blob(chunk)
            ),
        );
        if result.get("ok").is_none() {
            fail(format!("browse object chunk upload rejected: {result}"));
        }
    }
    let finalized = icp_json(
        canister,
        "finalize_chunked_object",
        &format!("(principal \"{owner}\", \"{repo}\", \"{oid}\")"),
    );
    if finalized.get("ok").is_none() {
        fail(format!(
            "chunked browse object finalization rejected: {finalized}"
        ));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        fail(
            "usage: infinigit-pack <upload|materialize|index-browse> <canister> <owner-principal> <repo> <bare-git-dir>",
        );
    }
    let path = Path::new(&args[5]);
    match args[1].as_str() {
        "upload" => upload(&args[2], &args[3], &args[4], path),
        "materialize" => materialize(&args[2], &args[3], &args[4], path),
        "index-browse" => index_browse_objects(&args[2], &args[3], &args[4], path),
        _ => fail("operation must be upload, materialize, or index-browse"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candid_blob_is_deterministic() {
        assert_eq!(candid_blob(&[0, 1, 255]), "vec {0;1;255}");
    }
    #[test]
    fn reads_trailing_git_pack_checksum() {
        let mut bytes = vec![1, 2, 3];
        bytes.extend(0u8..20);
        assert_eq!(pack_id(&bytes), "000102030405060708090a0b0c0d0e0f10111213");
    }
    #[test]
    fn selects_inline_and_chunked_object_boundaries() {
        assert!(should_inline_object(INLINE_OBJECT_LIMIT));
        assert!(!should_inline_object(INLINE_OBJECT_LIMIT + 1));
    }
}
