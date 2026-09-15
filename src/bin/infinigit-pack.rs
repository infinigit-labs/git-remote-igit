use candid_parser::candid::{
    IDLArgs, Principal, TypeEnv,
    types::{Label, value::IDLValue},
};
use candid_parser::{IDLProg, check_prog, parse_idl_args};
use ic_agent::{
    Agent, Identity,
    identity::{BasicIdentity, Prime256v1Identity, Secp256k1Identity},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};

const CHUNK_SIZE: usize = 512 * 1024;
const INLINE_OBJECT_LIMIT: usize = 128 * 1024;
const PACK_DID: &str = r#"
type Kind = variant { "blob"; "tree"; "commit"; "tag" };
type Ref = record { name : text; oid : text };
type Object = record { kind : Kind; payload : blob };
type ObjectEntry = record { oid : text; git_object : Object };
type Metadata = record { oid : text; kind : Kind; size : nat };
type RefChange = record { name : text; expected_old : opt text; new : opt text };
type RefTransactionReceipt = record { transaction_id : text; uploaded_pages : nat; change_count : nat; updated_at : int };
type ChunkReceipt = record { index : nat; uploaded_chunks : nat; chunk_count : nat };
type Chunked = record { oid : text; kind : Kind; total_size : nat; chunk_size : nat; chunk_count : nat; uploaded_chunks : vec nat; complete : bool };
type Pack = record { pack_id : text; total_size : nat; chunk_size : nat; chunk_count : nat; uploaded_chunks : vec nat; complete : bool; indexed_objects : nat };
type Prune = record { removed_packs : nat; removed_logical_bytes : nat; reclaimed_physical_bytes : nat };
type ResultRefs = variant { ok : vec Ref; err : text };
type ResultRefTransaction = variant { ok : RefTransactionReceipt; err : text };
type ResultTexts = variant { ok : vec text; err : text };
type ResultNat = variant { ok : nat; err : text };
type ResultChunk = variant { ok : ChunkReceipt; err : text };
type ResultChunked = variant { ok : Chunked; err : text };
type ResultPack = variant { ok : Pack; err : text };
type ResultPacks = variant { ok : vec Pack; err : text };
type ResultBlob = variant { ok : blob; err : text };
type ResultPrune = variant { ok : Prune; err : text };
service : {
  list_refs : (principal, text) -> (ResultRefs) query;
  list_packs : (principal, text) -> (ResultPacks) query;
  missing_objects : (principal, text, vec text, bool) -> (ResultTexts) query;
  begin_pack : (principal, text, text, nat, nat) -> (ResultPack);
  put_pack_chunk : (principal, text, text, nat, text, blob) -> (ResultChunk);
  finalize_pack : (principal, text, text) -> (ResultPack);
  list_pack_objects : (principal, text, text) -> (ResultTexts) query;
  index_pack_objects_batch : (principal, text, text, vec Metadata, bool) -> (ResultNat);
  put_objects_batch : (principal, text, vec ObjectEntry) -> (ResultTexts);
  update_refs_atomic : (principal, text, vec RefChange) -> (ResultRefs);
  stage_ref_transaction_page : (principal, text, text, nat, nat, vec RefChange) -> (ResultRefTransaction);
  commit_ref_transaction : (principal, text, text) -> (ResultRefs);
  abort_ref_transaction : (principal, text, text) -> (variant { ok; err : text });
  prune_packs : (principal, text, vec text) -> (ResultPrune);
  get_pack_chunk : (principal, text, text, nat) -> (ResultBlob) query;
  begin_chunked_object : (principal, text, text, Kind, nat, nat) -> (ResultChunked);
  put_object_chunk : (principal, text, text, nat, blob) -> (ResultChunk);
  finalize_chunked_object : (principal, text, text) -> (ResultChunked);
}"#;
static ARGUMENT_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static AGENT_CLIENT: OnceLock<Option<AgentClient>> = OnceLock::new();
static CANISTER_IDS: OnceLock<Mutex<BTreeMap<String, Principal>>> = OnceLock::new();

struct AgentClient {
    agent: Agent,
    runtime: tokio::runtime::Runtime,
    did: String,
    icp: String,
}

fn command_output(program: &str, args: &[String]) -> Option<Vec<u8>> {
    let output = Command::new(program).args(args).output().ok()?;
    output.status.success().then_some(output.stdout)
}

fn agent_client() -> Option<&'static AgentClient> {
    AGENT_CLIENT
        .get_or_init(|| {
            let network = env::var("INFINIGIT_AGENT_URL").ok().or_else(|| {
                match env::var("INFINIGIT_NETWORK").ok().as_deref() {
                    Some("ic") => Some("https://icp-api.io".into()),
                    Some(value) if value.contains("://") => Some(value.into()),
                    _ => None,
                }
            })?;
            let icp = env::var("INFINIGIT_ICP_BIN").unwrap_or_else(|_| "icp".into());
            let identity_name = env::var("INFINIGIT_IDENTITY").ok().or_else(|| {
                String::from_utf8(command_output(
                    &icp,
                    &["identity".into(), "default".into()],
                )?)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
            })?;
            let mut export_args = vec!["identity".into(), "export".into(), identity_name.clone()];
            if let Ok(path) = env::var("INFINIGIT_IDENTITY_PASSWORD_FILE") {
                export_args.extend(["--password-file".into(), path]);
            }
            let pem = command_output(&icp, &export_args)?;
            let identity: Arc<dyn Identity> = if let Ok(value) = Secp256k1Identity::from_pem(&pem) {
                Arc::new(value)
            } else if let Ok(value) = Prime256v1Identity::from_pem(&pem) {
                Arc::new(value)
            } else if let Ok(value) = BasicIdentity::from_pem(&pem) {
                Arc::new(value)
            } else {
                return None;
            };
            let expected = String::from_utf8(command_output(
                &icp,
                &[
                    "identity".into(),
                    "principal".into(),
                    "--identity".into(),
                    identity_name,
                ],
            )?)
            .ok()?
            .trim()
            .to_owned();
            if identity.sender().ok()?.to_text() != expected {
                return None;
            }
            let did = env::var("INFINIGIT_SHARD_CANDID")
                .ok()
                .and_then(|path| fs::read_to_string(path).ok())
                .unwrap_or_else(|| PACK_DID.into());
            let agent = Agent::builder()
                .with_url(network.clone())
                .with_arc_identity(identity)
                .build()
                .ok()?;
            let runtime = tokio::runtime::Runtime::new().ok()?;
            if network != "https://icp-api.io" && runtime.block_on(agent.fetch_root_key()).is_err()
            {
                return None;
            }
            Some(AgentClient {
                agent,
                runtime,
                did,
                icp,
            })
        })
        .as_ref()
}

fn canister_principal(client: &AgentClient, canister: &str) -> Result<Principal, String> {
    if let Ok(principal) = Principal::from_text(canister) {
        return Ok(principal);
    }
    let ids = CANISTER_IDS.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(principal) = ids.lock().map_err(|error| error.to_string())?.get(canister) {
        return Ok(*principal);
    }
    let output = command_output(
        &client.icp,
        &[
            "canister".into(),
            "status".into(),
            canister.into(),
            "--json".into(),
        ],
    )
    .ok_or_else(|| format!("cannot resolve canister name {canister}"))?;
    let status: Value = serde_json::from_slice(&output).map_err(|error| error.to_string())?;
    let id = status
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("canister status returned no id for {canister}"))?;
    let principal = Principal::from_text(id).map_err(|error| error.to_string())?;
    ids.lock()
        .map_err(|error| error.to_string())?
        .insert(canister.into(), principal);
    Ok(principal)
}

fn agent_json(
    client: &AgentClient,
    canister: &str,
    method: &str,
    argument: &str,
) -> Result<Value, String> {
    let ast = client
        .did
        .parse::<IDLProg>()
        .map_err(|error| error.to_string())?;
    let mut type_env = TypeEnv::new();
    let actor = check_prog(&mut type_env, &ast)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Candid contract has no service actor".to_owned())?;
    let signature = type_env
        .get_method(&actor, method)
        .map_err(|error| error.to_string())?;
    let args = parse_idl_args(argument)
        .map_err(|error| error.to_string())?
        .to_bytes_with_types(&type_env, &signature.args)
        .map_err(|error| error.to_string())?;
    let principal = canister_principal(client, canister)?;
    let bytes = if signature.is_query() {
        client
            .runtime
            .block_on(client.agent.query(&principal, method).with_arg(args).call())
            .map_err(|error| error.to_string())?
    } else {
        client
            .runtime
            .block_on(
                client
                    .agent
                    .update(&principal, method)
                    .with_arg(args)
                    .call_and_wait(),
            )
            .map_err(|error| error.to_string())?
    };
    let decoded = IDLArgs::from_bytes_with_types(&bytes, &type_env, &signature.rets)
        .map_err(|error| error.to_string())?;
    Ok(decoded
        .args
        .into_iter()
        .next()
        .map(idl_json)
        .unwrap_or(Value::Null))
}

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
    if let Ok(path) = env::var("INFINIGIT_TRANSPORT_TRACE") {
        if let Ok(mut trace) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(trace, "{method}");
        }
    }
    if let Some(client) = agent_client() {
        return agent_json(client, canister, method, argument).unwrap_or_else(|error| {
            fail(format!("direct ICP agent call failed ({method}): {error}"))
        });
    }
    if env::var("INFINIGIT_REQUIRE_AGENT").ok().as_deref() == Some("1") {
        fail("command-scoped ICP agent is unavailable")
    }
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
    if let Some(path) = env::var_os("INFINIGIT_IDENTITY_PASSWORD_FILE") {
        command.arg("--identity-password-file").arg(path);
    }
    if let Some(network) = env::var_os("INFINIGIT_NETWORK") {
        command.arg("--network").arg(network);
        if let Some(root_key) = env::var_os("INFINIGIT_ROOT_KEY") {
            command.arg("--root-key").arg(root_key);
        }
    } else if let Some(root) = env::var_os("INFINIGIT_PROJECT_ROOT") {
        command.arg("--project-root-override").arg(root);
    }
    let output = command
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| fail(e.to_string()));
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

fn parallel_icp_calls(canister: &str, calls: Vec<(String, String)>) -> Vec<Value> {
    let concurrency = env::var("INFINIGIT_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 16);
    let mut results = Vec::with_capacity(calls.len());
    for group in calls.chunks(concurrency) {
        let mut values = Vec::with_capacity(group.len());
        std::thread::scope(|scope| {
            let handles = group
                .iter()
                .map(|(method, argument)| scope.spawn(move || icp_json(canister, method, argument)))
                .collect::<Vec<_>>();
            for handle in handles {
                values.push(
                    handle
                        .join()
                        .unwrap_or_else(|_| fail("parallel canister call panicked")),
                )
            }
        });
        results.extend(values);
    }
    results
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

fn all_object_ids(git_dir: &Path) -> Vec<String> {
    let output = git(git_dir, &["rev-list", "--objects", "--all"]);
    let mut ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn missing_objects(
    canister: &str,
    owner: &str,
    repo: &str,
    ids: &[String],
    browse_only: bool,
) -> Vec<String> {
    let mut missing = Vec::new();
    for batch in ids.chunks(500) {
        let values = batch
            .iter()
            .map(|oid| format!("\"{oid}\""))
            .collect::<Vec<_>>()
            .join(";");
        let result = icp_json(
            canister,
            "missing_objects",
            &format!("(principal \"{owner}\", \"{repo}\", vec {{{values}}}, {browse_only})"),
        );
        missing.extend(
            result
                .get("ok")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail(format!("object negotiation rejected: {result}")))
                .iter()
                .map(|value| value.as_str().unwrap().to_owned()),
        );
    }
    missing
}

fn create_incremental_pack(git_dir: &Path, ids: &[String]) -> Option<String> {
    if ids.is_empty() {
        return None;
    }
    let pack_dir = git_dir.join("objects/pack");
    fs::create_dir_all(&pack_dir).unwrap_or_else(|error| fail(error.to_string()));
    let base = pack_dir.join("pack");
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["pack-objects", base.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| fail(format!("cannot start git pack-objects: {error}")));
    {
        let input = child.stdin.as_mut().unwrap();
        for oid in ids {
            writeln!(input, "{oid}").unwrap_or_else(|error| fail(error.to_string()));
        }
    }
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| fail(error.to_string()));
    if !output.status.success() {
        fail("git pack-objects failed")
    }
    let id = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if id.len() != 40 {
        fail("git pack-objects returned an invalid pack id")
    }
    Some(id)
}

fn canister_pack_ids(canister: &str, owner: &str, repo: &str) -> Vec<String> {
    let result = icp_json(
        canister,
        "list_packs",
        &format!("(principal \"{owner}\", \"{repo}\")"),
    );
    result
        .get("ok")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail(format!("pack listing rejected: {result}")))
        .iter()
        .filter_map(|pack| {
            pack.get("pack_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn candid_ref_changes(expected: &[(String, String)], desired: &[(String, String)]) -> Vec<String> {
    let names = expected
        .iter()
        .map(|v| &v.0)
        .chain(desired.iter().map(|v| &v.0))
        .collect::<BTreeSet<_>>();
    names
        .into_iter()
        .filter_map(|name| {
            let old = expected.iter().find(|v| &v.0 == name).map(|v| v.1.as_str());
            let new = desired.iter().find(|v| &v.0 == name).map(|v| v.1.as_str());
            (old != new).then(|| {
                format!(
                    "record {{ name = \"{name}\"; expected_old = {}; new = {} }}",
                    old.map(|v| format!("opt \"{v}\""))
                        .unwrap_or_else(|| "null".into()),
                    new.map(|v| format!("opt \"{v}\""))
                        .unwrap_or_else(|| "null".into())
                )
            })
        })
        .collect()
}

fn publish_ref_changes(canister: &str, owner: &str, repo: &str, changes: &[String]) {
    if changes.is_empty() {
        return;
    }
    if changes.len() <= 100 {
        let result = icp_json(
            canister,
            "update_refs_atomic",
            &format!(
                "(principal \"{owner}\", \"{repo}\", vec {{{}}})",
                changes.join(";")
            ),
        );
        if result.get("ok").is_none() {
            fail(format!("atomic ref publication rejected: {result}"));
        }
        return;
    }
    let transaction_id = format!("{:x}", Sha256::digest(changes.join(";").as_bytes()));
    let pages = changes.chunks(100).collect::<Vec<_>>();
    for (index, page) in pages.iter().enumerate() {
        let result = icp_json(
            canister,
            "stage_ref_transaction_page",
            &format!(
                "(principal \"{owner}\", \"{repo}\", \"{transaction_id}\", {} : nat, {index} : nat, vec {{{}}})",
                pages.len(),
                page.join(";")
            ),
        );
        if result.get("ok").is_none() {
            let _ = icp_json(
                canister,
                "abort_ref_transaction",
                &format!("(principal \"{owner}\", \"{repo}\", \"{transaction_id}\")"),
            );
            fail(format!("ref transaction page rejected: {result}"));
        }
    }
    let result = icp_json(
        canister,
        "commit_ref_transaction",
        &format!("(principal \"{owner}\", \"{repo}\", \"{transaction_id}\")"),
    );
    if result.get("ok").is_none() {
        fail(format!("atomic ref transaction rejected: {result}"));
    }
}

fn upload(canister: &str, owner: &str, repo: &str, git_dir: &Path) {
    let expected_refs = canister_refs(canister, owner, repo);
    let mut desired_pack_ids = canister_pack_ids(canister, owner, repo);
    let missing = missing_objects(canister, owner, repo, &all_object_ids(git_dir), false);
    if desired_pack_ids.len() >= 90 {
        git(git_dir, &["repack", "-a", "-d"]);
        desired_pack_ids.clear();
        let pack_dir = git_dir.join("objects/pack");
        desired_pack_ids.extend(
            fs::read_dir(pack_dir)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|value| value == "pack"))
                .map(|path| pack_id(&fs::read(path).unwrap())),
        );
    } else if let Some(id) = create_incremental_pack(git_dir, &missing) {
        desired_pack_ids.push(id)
    }
    desired_pack_ids.sort();
    desired_pack_ids.dedup();
    let pack_dir = git_dir.join("objects/pack");
    for id in desired_pack_ids.clone() {
        let path = pack_dir.join(format!("pack-{id}.pack"));
        let bytes = fs::read(&path).unwrap_or_else(|e| fail(e.to_string()));
        if pack_id(&bytes) != id {
            fail(format!("local pack checksum mismatch: {id}"))
        }
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
            let calls = bytes
                .chunks(CHUNK_SIZE)
                .enumerate()
                .map(|(index, chunk)| {
                    let digest = format!("{:x}", Sha256::digest(chunk));
                    let argument = format!(
                        "(principal \"{owner}\", \"{repo}\", \"{id}\", {index}, \"{digest}\", {})",
                        candid_blob(chunk)
                    );
                    ("put_pack_chunk".into(), argument)
                })
                .collect::<Vec<_>>();
            for result in parallel_icp_calls(canister, calls) {
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
        let listed = icp_json(
            canister,
            "list_pack_objects",
            &format!("(principal \"{owner}\", \"{repo}\", \"{id}\")"),
        );
        let already = listed
            .get("ok")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let pending = objects
            .iter()
            .filter(|object| !already.contains(object.oid.as_str()))
            .collect::<Vec<_>>();
        for (batch_index, batch) in pending.chunks(500).enumerate() {
            let candid_objects = batch
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
                "index_pack_objects_batch",
                &format!(
                    "(principal \"{owner}\", \"{repo}\", \"{id}\", vec {{{candid_objects}}}, {})",
                    already.is_empty() && batch_index == 0
                ),
            );
            if indexed.get("ok").is_none() {
                fail(format!("pack index batch rejected: {indexed}"));
            }
        }
    }

    // Browser repository views read canonical loose objects through get_object.
    // Publish those objects before moving refs so a newly visible commit can
    // never point at a tree/blob that the browser cannot load.
    index_browse_objects(canister, owner, repo, git_dir);

    let desired_refs = local_refs(git_dir);
    let changes = candid_ref_changes(&expected_refs, &desired_refs);
    publish_ref_changes(canister, owner, repo, &changes);
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
        let path = pack_dir.join(format!("pack-{id}.pack"));
        if fs::read(&path).is_ok_and(|bytes| bytes.len() >= 20 && pack_id(&bytes) == id) {
            let index = path.with_extension("idx");
            if !index.exists() {
                git(git_dir, &["index-pack", path.to_str().unwrap()]);
            }
            continue;
        }
        let calls = (0..count)
            .map(|index| {
                (
                    "get_pack_chunk".into(),
                    format!("(principal \"{owner}\", \"{repo}\", \"{id}\", {index})"),
                )
            })
            .collect();
        let mut bytes = Vec::new();
        for chunk in parallel_icp_calls(canister, calls) {
            let data = chunk
                .get("ok")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail(format!("chunk download rejected: {chunk}")));
            bytes.extend(data.iter().map(|value| value.as_u64().unwrap() as u8));
        }
        if pack_id(&bytes) != id {
            fail(format!("pack checksum mismatch: {id}"));
        }
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
    let object_ids = all_object_ids(git_dir);
    let missing = missing_objects(canister, owner, repo, &object_ids, true);
    let mut batch = Vec::<(String, String, Vec<u8>)>::new();
    let mut batch_bytes = 0usize;
    let flush = |batch: &mut Vec<(String, String, Vec<u8>)>, batch_bytes: &mut usize| {
        if batch.is_empty() {
            return;
        }
        let objects = batch.iter().map(|(oid, kind, payload)| format!("record {{ oid = \"{oid}\"; git_object = record {{ kind = variant {{ \"{kind}\" }}; payload = {} }} }}", candid_blob(payload))).collect::<Vec<_>>().join(";");
        let result = icp_json(
            canister,
            "put_objects_batch",
            &format!("(principal \"{owner}\", \"{repo}\", vec {{{objects}}})"),
        );
        if result.get("ok").is_none() {
            fail(format!("browse object batch rejected: {result}"))
        }
        batch.clear();
        *batch_bytes = 0;
    };
    for oid in missing {
        let kind_output = git(git_dir, &["cat-file", "-t", &oid]);
        let kind = String::from_utf8_lossy(&kind_output.stdout)
            .trim()
            .to_owned();
        if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
            fail(format!("unsupported browse object type: {kind}"));
        }
        let payload = git(git_dir, &["cat-file", &kind, &oid]).stdout;
        if should_inline_object(payload.len()) {
            if batch.len() == 100 || batch_bytes + payload.len() > 1_250_000 {
                flush(&mut batch, &mut batch_bytes)
            }
            batch_bytes += payload.len();
            batch.push((oid, kind, payload));
        } else {
            flush(&mut batch, &mut batch_bytes);
            index_browse_object(canister, owner, repo, &oid, &kind, &payload);
        }
    }
    flush(&mut batch, &mut batch_bytes);
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
    let calls = payload
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| {
            (
                "put_object_chunk".into(),
                format!(
                    "(principal \"{owner}\", \"{repo}\", \"{oid}\", {index}, {})",
                    candid_blob(chunk)
                ),
            )
        })
        .collect::<Vec<_>>();
    for result in parallel_icp_calls(canister, calls) {
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
    #[test]
    fn emits_only_changed_ref_operations_including_deletions() {
        let expected = vec![
            ("refs/heads/main".into(), "11".repeat(20)),
            ("refs/heads/old".into(), "22".repeat(20)),
        ];
        let desired = vec![
            ("refs/heads/main".into(), "11".repeat(20)),
            ("refs/heads/new".into(), "33".repeat(20)),
        ];
        let changes = candid_ref_changes(&expected, &desired);
        let changes = changes.join(";");
        assert!(!changes.contains("refs/heads/main"));
        assert!(changes.contains("refs/heads/old") && changes.contains("new = null"));
        assert!(changes.contains("refs/heads/new") && changes.contains("expected_old = null"));
    }
    #[test]
    fn embedded_agent_contract_covers_every_transport_call() {
        let ast = PACK_DID.parse::<IDLProg>().unwrap();
        let mut env = TypeEnv::new();
        let actor = check_prog(&mut env, &ast).unwrap().unwrap();
        for method in [
            "list_refs",
            "list_packs",
            "missing_objects",
            "begin_pack",
            "put_pack_chunk",
            "finalize_pack",
            "list_pack_objects",
            "index_pack_objects_batch",
            "put_objects_batch",
            "update_refs_atomic",
            "stage_ref_transaction_page",
            "commit_ref_transaction",
            "abort_ref_transaction",
            "prune_packs",
            "get_pack_chunk",
            "begin_chunked_object",
            "put_object_chunk",
            "finalize_chunked_object",
        ] {
            assert!(env.get_method(&actor, method).is_ok(), "missing {method}");
        }
    }
}
