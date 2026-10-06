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
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const CHUNK_SIZE: usize = 512 * 1024;
const INLINE_OBJECT_LIMIT: usize = 128 * 1024;
const DEFAULT_PACK_SEGMENT_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 120;
const DEFAULT_CALL_ATTEMPTS: usize = 4;
const PACK_DID: &str = r#"
type Kind = variant { "blob"; "tree"; "commit"; "tag" };
type Ref = record { name : text; oid : text };
type Object = record { kind : Kind; payload : blob };
type ObjectEntry = record { oid : text; git_object : Object };
type Metadata = record { oid : text; kind : Kind; size : nat };
type MetadataV3 = record { oid : text; kind : Kind; size : nat; offset : nat; packed_length : nat };
type PackChunkUpload = record { index : nat; digest : text; payload : blob };
type TransportCapabilities = record { version : nat; max_chunk_batch_items : nat; max_chunk_batch_bytes : nat; max_pack_index_batch_items : nat; max_download_batch_items : nat; max_retained_packs : nat; packed_object_reads : bool; streaming_pack_downloads : bool };
type TransportSnapshot = record { generation : text; unchanged : bool; refs : vec Ref; packs : vec Pack; capabilities : TransportCapabilities };
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
  transport_capabilities : () -> (TransportCapabilities) query;
  transport_snapshot : (principal, text, opt text) -> (variant { ok : TransportSnapshot; err : text }) query;
  put_pack_chunks : (principal, text, text, vec PackChunkUpload) -> (variant { ok : vec ChunkReceipt; err : text });
  finalize_pack : (principal, text, text) -> (ResultPack);
  list_pack_objects : (principal, text, text) -> (ResultTexts) query;
  index_pack_objects_batch : (principal, text, text, vec Metadata, bool) -> (ResultNat);
  index_pack_objects_batch_v2 : (principal, text, text, vec Metadata, bool) -> (ResultNat);
  index_pack_objects_batch_v3 : (principal, text, text, vec MetadataV3, bool) -> (ResultNat);
  put_objects_batch : (principal, text, vec ObjectEntry) -> (ResultTexts);
  update_refs_atomic : (principal, text, vec RefChange) -> (ResultRefs);
  stage_ref_transaction_page : (principal, text, text, nat, nat, vec RefChange) -> (ResultRefTransaction);
  commit_ref_transaction : (principal, text, text) -> (ResultRefs);
  abort_ref_transaction : (principal, text, text) -> (variant { ok; err : text });
  prune_packs : (principal, text, vec text) -> (ResultPrune);
  get_pack_chunk : (principal, text, text, nat) -> (ResultBlob) query;
  get_pack_chunks : (principal, text, text, vec nat) -> (variant { ok : vec blob; err : text }) query;
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

#[derive(Clone, Copy, Debug)]
struct TransportCapabilities {
    version: usize,
    max_chunk_batch_items: usize,
    max_chunk_batch_bytes: usize,
    max_pack_index_batch_items: usize,
    max_download_batch_items: usize,
    max_retained_packs: usize,
    packed_object_reads: bool,
    _streaming_pack_downloads: bool,
}

struct TransportSnapshot {
    capabilities: TransportCapabilities,
    refs: Vec<(String, String)>,
    packs: BTreeMap<String, usize>,
    pack_values: Vec<Value>,
    raw: Value,
}

impl Default for TransportCapabilities {
    fn default() -> Self {
        Self {
            version: 1,
            max_chunk_batch_items: 1,
            max_chunk_batch_bytes: CHUNK_SIZE,
            max_pack_index_batch_items: 500,
            max_download_batch_items: 1,
            max_retained_packs: 100,
            packed_object_reads: false,
            _streaming_pack_downloads: false,
        }
    }
}

struct TransportTimer {
    operation: &'static str,
    started: Instant,
    checkpoint: Instant,
}

impl TransportTimer {
    fn new(operation: &'static str) -> Self {
        let now = Instant::now();
        Self {
            operation,
            started: now,
            checkpoint: now,
        }
    }

    fn mark(&mut self, phase: &str) {
        if env::var("INFINIGIT_TRANSPORT_TIMINGS").ok().as_deref() == Some("1") {
            let now = Instant::now();
            eprintln!(
                "infinigit transport: operation={} phase={} phase_ms={} total_ms={}",
                self.operation,
                phase,
                now.duration_since(self.checkpoint).as_millis(),
                now.duration_since(self.started).as_millis()
            );
            self.checkpoint = now;
        }
    }
}

struct TransferProgress {
    label: &'static str,
    unit: &'static str,
    completed: u64,
    total: u64,
    started: Instant,
    last_reported: Instant,
}

impl TransferProgress {
    fn new(label: &'static str, unit: &'static str, total: u64, completed: u64) -> Self {
        let now = Instant::now();
        let progress = Self {
            label,
            unit,
            completed,
            total,
            started: now,
            last_reported: now,
        };
        progress.print();
        progress
    }

    fn advance(&mut self, amount: u64) {
        self.completed = self.completed.saturating_add(amount).min(self.total);
        if self.completed == self.total || self.last_reported.elapsed() >= Duration::from_secs(2) {
            self.print();
            self.last_reported = Instant::now();
        }
    }

    fn print(&self) {
        let percent = if self.total == 0 {
            100.0
        } else {
            self.completed as f64 * 100.0 / self.total as f64
        };
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        if self.unit == "bytes" {
            let rate = self.completed as f64 / elapsed / (1024.0 * 1024.0);
            eprintln!(
                "infinigit: {} {}/{} bytes ({percent:.1}%, {rate:.1} MiB/s)",
                self.label, self.completed, self.total
            );
        } else {
            let rate = self.completed as f64 / elapsed;
            eprintln!(
                "infinigit: {} {}/{} {} ({percent:.1}%, {rate:.1}/s)",
                self.label, self.completed, self.total, self.unit
            );
        }
    }
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

fn agent_json_attempt(
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
    let timeout = Duration::from_secs(
        env::var("INFINIGIT_CALL_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_CALL_TIMEOUT_SECS),
    );
    let bytes = if signature.is_query() {
        client.runtime.block_on(async {
            tokio::time::timeout(
                timeout,
                client.agent.query(&principal, method).with_arg(args).call(),
            )
            .await
            .map_err(|_| format!("{method} timed out after {} seconds", timeout.as_secs()))?
            .map_err(|error| error.to_string())
        })?
    } else {
        client.runtime.block_on(async {
            tokio::time::timeout(
                timeout,
                client
                    .agent
                    .update(&principal, method)
                    .with_arg(args)
                    .call_and_wait(),
            )
            .await
            .map_err(|_| format!("{method} timed out after {} seconds", timeout.as_secs()))?
            .map_err(|error| error.to_string())
        })?
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

fn retryable_method(method: &str) -> bool {
    matches!(
        method,
        "transport_capabilities"
            | "transport_snapshot"
            | "list_refs"
            | "list_packs"
            | "missing_objects"
            | "begin_pack"
            | "put_pack_chunk"
            | "put_pack_chunks"
            | "finalize_pack"
            | "list_pack_objects"
            | "index_pack_objects_batch"
            | "index_pack_objects_batch_v2"
            | "index_pack_objects_batch_v3"
            | "put_objects_batch"
            | "begin_chunked_object"
            | "put_object_chunk"
            | "finalize_chunked_object"
            | "get_pack_chunk"
            | "get_pack_chunks"
    )
}

fn agent_json(
    client: &AgentClient,
    canister: &str,
    method: &str,
    argument: &str,
) -> Result<Value, String> {
    let attempts = if retryable_method(method) {
        env::var("INFINIGIT_CALL_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(DEFAULT_CALL_ATTEMPTS)
            .clamp(1, 10)
    } else {
        1
    };
    let mut last_error = String::new();
    for attempt in 1..=attempts {
        match agent_json_attempt(client, canister, method, argument) {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = error;
                if attempt < attempts {
                    let delay = Duration::from_millis(250u64.saturating_mul(1 << (attempt - 1)));
                    eprintln!(
                        "infinigit: {method} attempt {attempt}/{attempts} failed; retrying in {} ms: {last_error}",
                        delay.as_millis()
                    );
                    std::thread::sleep(delay);
                }
            }
        }
    }
    Err(format!(
        "{method} failed after {attempts} attempts: {last_error}"
    ))
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

fn json_usize(value: &Value, field: &str) -> Option<usize> {
    let value = value.get(field)?;
    value
        .as_u64()
        .map(|number| number as usize)
        .or_else(|| value.as_str()?.replace('_', "").parse().ok())
}

fn transport_capabilities(canister: &str) -> TransportCapabilities {
    if env::var("INFINIGIT_DISABLE_TRANSPORT_V2").ok().as_deref() == Some("1") {
        return TransportCapabilities::default();
    }
    let Some(client) = agent_client() else {
        return TransportCapabilities::default();
    };
    let value = match agent_json(client, canister, "transport_capabilities", "()") {
        Ok(value) => value,
        Err(error) => {
            if env::var("INFINIGIT_TRANSPORT_DEBUG").ok().as_deref() == Some("1") {
                eprintln!("infinigit-pack: transport v2 unavailable: {error}");
            }
            return TransportCapabilities::default();
        }
    };
    if env::var("INFINIGIT_TRANSPORT_DEBUG").ok().as_deref() == Some("1") {
        eprintln!("infinigit-pack: transport capabilities: {value}");
    }
    capabilities_from_value(&value)
}

fn capabilities_from_value(value: &Value) -> TransportCapabilities {
    TransportCapabilities {
        version: json_usize(&value, "version").unwrap_or(1),
        max_chunk_batch_items: json_usize(&value, "max_chunk_batch_items")
            .unwrap_or(1)
            .clamp(1, 16),
        max_chunk_batch_bytes: json_usize(&value, "max_chunk_batch_bytes")
            .unwrap_or(CHUNK_SIZE)
            .clamp(CHUNK_SIZE, 1_450_000),
        max_pack_index_batch_items: json_usize(&value, "max_pack_index_batch_items")
            .unwrap_or(500)
            .clamp(1, 2_000),
        max_download_batch_items: json_usize(&value, "max_download_batch_items")
            .unwrap_or(1)
            .clamp(1, 3),
        max_retained_packs: json_usize(&value, "max_retained_packs")
            .unwrap_or(100)
            .clamp(100, 1_000),
        packed_object_reads: value
            .get("packed_object_reads")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _streaming_pack_downloads: value
            .get("streaming_pack_downloads")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn transport_snapshot(
    canister: &str,
    owner: &str,
    repo: &str,
    git_dir: &Path,
) -> Option<TransportSnapshot> {
    if env::var("INFINIGIT_DISABLE_TRANSPORT_V2").ok().as_deref() == Some("1") {
        return None;
    }
    let client = agent_client()?;
    if let Ok(path) = env::var("INFINIGIT_TRANSPORT_TRACE") {
        if let Ok(mut trace) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(trace, "transport_snapshot");
        }
    }
    let cache_path = git_dir.join("infinigit-transport-manifest.json");
    let cached: Option<Value> = fs::read(&cache_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let known = cached
        .as_ref()
        .and_then(|value| value.get("generation"))
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let known_argument = known
        .map(|value| format!("opt \"{value}\""))
        .unwrap_or_else(|| "null".into());
    let value = agent_json(
        client,
        canister,
        "transport_snapshot",
        &format!("(principal \"{owner}\", \"{repo}\", {known_argument})"),
    )
    .ok()?;
    let snapshot = value.get("ok")?;
    if snapshot.get("unchanged").and_then(Value::as_bool) == Some(true) {
        return parse_transport_snapshot(cached.as_ref()?);
    }
    let encoded = serde_json::to_vec(snapshot).ok()?;
    let incoming = cache_path.with_extension("json.incoming");
    if fs::write(&incoming, encoded).is_ok() {
        let _ = fs::rename(incoming, cache_path);
    }
    let refs = snapshot
        .get("refs")?
        .as_array()?
        .iter()
        .map(|entry| {
            Some((
                entry.get("name")?.as_str()?.to_owned(),
                entry.get("oid")?.as_str()?.to_owned(),
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let pack_values = snapshot.get("packs")?.as_array()?.clone();
    let packs = pack_values
        .iter()
        .filter_map(|pack| {
            Some((
                pack.get("pack_id")?.as_str()?.to_owned(),
                json_usize(pack, "indexed_objects").unwrap_or(0),
            ))
        })
        .collect();
    Some(TransportSnapshot {
        capabilities: capabilities_from_value(snapshot.get("capabilities")?),
        refs,
        packs,
        pack_values,
        raw: snapshot.clone(),
    })
}

fn session_snapshot_path(git_dir: &Path) -> Option<std::path::PathBuf> {
    env::var("INFINIGIT_TRANSPORT_SESSION")
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .map(|_| git_dir.join("infinigit-transport-snapshot.json"))
}

fn store_session_snapshot(git_dir: &Path, snapshot: &TransportSnapshot) {
    let Some(path) = session_snapshot_path(git_dir) else {
        return;
    };
    let session = env::var("INFINIGIT_TRANSPORT_SESSION").unwrap();
    let value = serde_json::json!({ "session": session, "snapshot": snapshot.raw });
    fs::write(path, serde_json::to_vec(&value).unwrap())
        .unwrap_or_else(|error| fail(format!("cannot cache transport snapshot: {error}")));
}

fn take_session_snapshot(git_dir: &Path) -> Option<TransportSnapshot> {
    let path = session_snapshot_path(git_dir)?;
    let bytes = fs::read(&path).ok()?;
    let _ = fs::remove_file(path);
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    if value.get("session")?.as_str()? != env::var("INFINIGIT_TRANSPORT_SESSION").ok()? {
        return None;
    }
    parse_transport_snapshot(value.get("snapshot")?)
}

fn parse_transport_snapshot(snapshot: &Value) -> Option<TransportSnapshot> {
    let refs = snapshot
        .get("refs")?
        .as_array()?
        .iter()
        .map(|entry| {
            Some((
                entry.get("name")?.as_str()?.to_owned(),
                entry.get("oid")?.as_str()?.to_owned(),
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let pack_values = snapshot.get("packs")?.as_array()?.clone();
    let packs = pack_values
        .iter()
        .filter_map(|pack| {
            Some((
                pack.get("pack_id")?.as_str()?.to_owned(),
                json_usize(pack, "indexed_objects").unwrap_or(0),
            ))
        })
        .collect();
    Some(TransportSnapshot {
        capabilities: capabilities_from_value(snapshot.get("capabilities")?),
        refs,
        packs,
        pack_values,
        raw: snapshot.clone(),
    })
}

fn for_parallel_icp_calls(
    canister: &str,
    calls: Vec<(String, String)>,
    mut consume: impl FnMut(Value),
) {
    let automatic = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(2)
        .clamp(4, 12);
    let concurrency = env::var("INFINIGIT_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(automatic.min(calls.len().max(1)))
        .clamp(1, 16);
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
        for value in values {
            consume(value);
        }
    }
}

fn parallel_icp_calls(canister: &str, calls: Vec<(String, String)>) -> Vec<Value> {
    let mut results = Vec::with_capacity(calls.len());
    for_parallel_icp_calls(canister, calls, |value| results.push(value));
    results
}

fn for_bounded_icp_calls<I>(canister: &str, calls: I, mut consume: impl FnMut(Value))
where
    I: IntoIterator<Item = (String, String)>,
{
    let automatic = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(2)
        .clamp(4, 12);
    let concurrency = env::var("INFINIGIT_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(automatic)
        .clamp(1, 16);
    let mut calls = calls.into_iter();
    loop {
        let group = calls.by_ref().take(concurrency).collect::<Vec<_>>();
        if group.is_empty() {
            break;
        }
        for_parallel_icp_calls(canister, group, &mut consume);
    }
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

fn for_each_git_object(
    git_dir: &Path,
    ids: &[String],
    mut consume: impl FnMut(String, String, Vec<u8>),
) {
    if ids.is_empty() {
        return;
    }
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| fail(format!("cannot start git cat-file batch: {error}")));
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for oid in ids {
                writeln!(input, "{oid}")?;
            }
            Ok(())
        });
        for expected_oid in ids {
            let mut header = String::new();
            output
                .read_line(&mut header)
                .unwrap_or_else(|error| fail(format!("cannot read git cat-file header: {error}")));
            let fields = header.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 || fields[0] != expected_oid || fields[1] == "missing" {
                fail(format!(
                    "invalid git cat-file response for {expected_oid}: {header}"
                ));
            }
            let kind = fields[1].to_owned();
            if !matches!(kind.as_str(), "blob" | "tree" | "commit" | "tag") {
                fail(format!("unsupported browse object type: {kind}"));
            }
            let size = fields[2]
                .parse::<usize>()
                .unwrap_or_else(|_| fail(format!("invalid git object size: {}", fields[2])));
            let mut payload = vec![0; size];
            output
                .read_exact(&mut payload)
                .unwrap_or_else(|error| fail(format!("cannot read git object: {error}")));
            let mut terminator = [0];
            output.read_exact(&mut terminator).unwrap_or_else(|error| {
                fail(format!("cannot read git object terminator: {error}"))
            });
            if terminator != [b'\n'] {
                fail("invalid git cat-file object terminator");
            }
            consume(expected_oid.clone(), kind, payload);
        }
        writer
            .join()
            .unwrap_or_else(|_| fail("git cat-file input writer panicked"))
            .unwrap_or_else(|error| fail(format!("cannot write git cat-file input: {error}")));
    });
    let status = child
        .wait()
        .unwrap_or_else(|error| fail(format!("cannot wait for git cat-file batch: {error}")));
    if !status.success() {
        fail("git cat-file batch failed");
    }
}

#[cfg(test)]
fn read_git_objects(git_dir: &Path, ids: &[String]) -> Vec<(String, String, Vec<u8>)> {
    let mut objects = Vec::with_capacity(ids.len());
    for_each_git_object(git_dir, ids, |oid, kind, payload| {
        objects.push((oid, kind, payload))
    });
    objects
}

fn non_blob_object_ids(git_dir: &Path, ids: &[String]) -> Vec<String> {
    if ids.is_empty() {
        return Vec::new();
    }
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|error| fail(format!("cannot start git cat-file batch-check: {error}")));
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut result = Vec::new();
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for oid in ids {
                writeln!(input, "{oid}")?;
            }
            Ok(())
        });
        for _ in ids {
            let mut line = String::new();
            output.read_line(&mut line).unwrap_or_else(|error| {
                fail(format!("cannot read git batch-check output: {error}"))
            });
            let (oid, kind) = line
                .trim_end()
                .split_once(' ')
                .unwrap_or_else(|| fail(format!("invalid git batch-check response: {line}")));
            if kind != "blob" {
                result.push(oid.to_owned());
            }
        }
        writer
            .join()
            .unwrap_or_else(|_| fail("git batch-check input writer panicked"))
            .unwrap_or_else(|error| fail(format!("cannot write git batch-check input: {error}")));
    });
    let status = child
        .wait()
        .unwrap_or_else(|error| fail(format!("cannot wait for git batch-check: {error}")));
    if !status.success() {
        fail("git cat-file batch-check failed");
    }
    result
}

#[cfg(test)]
fn pack_id(bytes: &[u8]) -> String {
    assert!(bytes.len() >= 20);
    bytes[bytes.len() - 20..]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pack_id_from_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let length = file.metadata().map_err(|error| error.to_string())?.len();
    if length < 20 {
        return Err("pack is shorter than its checksum".into());
    }
    file.seek(SeekFrom::End(-20))
        .map_err(|error| error.to_string())?;
    let mut checksum = [0u8; 20];
    file.read_exact(&mut checksum)
        .map_err(|error| error.to_string())?;
    Ok(checksum
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect())
}

struct PackObjectMetadata {
    oid: String,
    kind: String,
    size: u64,
    offset: u64,
    packed_length: u64,
}

fn pack_index_call(
    capabilities: &TransportCapabilities,
    owner: &str,
    repo: &str,
    pack_id: &str,
    batch: &[&PackObjectMetadata],
    reset: bool,
) -> (String, String) {
    let objects = batch
        .iter()
        .map(|object| if capabilities.version >= 4 {
            format!("record {{ oid = \"{}\"; kind = variant {{ \"{}\" }}; size = {}; offset = {}; packed_length = {} }}", object.oid, object.kind, object.size, object.offset, object.packed_length)
        } else {
            format!("record {{ oid = \"{}\"; kind = variant {{ \"{}\" }}; size = {} }}", object.oid, object.kind, object.size)
        })
        .collect::<Vec<_>>()
        .join(";");
    (
        if capabilities.version >= 4 {
            "index_pack_objects_batch_v3".into()
        } else if capabilities.version >= 2 {
            "index_pack_objects_batch_v2".into()
        } else {
            "index_pack_objects_batch".into()
        },
        format!("(principal \"{owner}\", \"{repo}\", \"{pack_id}\", vec {{{objects}}}, {reset})"),
    )
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
            let packed_length = fields.get(3)?.parse::<u64>().ok()?;
            let offset = fields.get(4)?.parse::<u64>().ok()?;
            (oid.len() == 40
                && oid.bytes().all(|c| c.is_ascii_hexdigit())
                && matches!(kind, "blob" | "tree" | "commit" | "tag"))
            .then(|| PackObjectMetadata {
                oid: oid.to_owned(),
                kind: kind.to_owned(),
                size,
                offset,
                packed_length,
            })
        })
        .collect()
}

fn pack_index_object_count(path: &Path) -> Option<usize> {
    let mut file = fs::File::open(path).ok()?;
    let mut prefix = [0u8; 8];
    file.read_exact(&mut prefix).ok()?;
    let fanout_start = if prefix[..4] == [0xff, b't', b'O', b'c'] {
        8
    } else {
        0
    };
    file.seek(SeekFrom::Start((fanout_start + 255 * 4) as u64))
        .ok()?;
    let mut count = [0u8; 4];
    file.read_exact(&mut count).ok()?;
    Some(u32::from_be_bytes(count) as usize)
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

fn replace_local_refs(git_dir: &Path, remote_refs: &[(String, String)]) {
    let desired_names = remote_refs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    let mut commands = String::from("start\n");
    for (name, _) in local_refs(git_dir) {
        if !desired_names.contains(name.as_str()) {
            commands.push_str(&format!("delete {name}\n"));
        }
    }
    for (name, oid) in remote_refs {
        commands.push_str(&format!("update {name} {oid}\n"));
    }
    commands.push_str("prepare\ncommit\n");
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["update-ref", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| fail(format!("cannot start git update-ref transaction: {error}")));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(commands.as_bytes())
        .unwrap_or_else(|error| fail(format!("cannot write git update-ref transaction: {error}")));
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap_or_else(|error| {
        fail(format!(
            "cannot wait for git update-ref transaction: {error}"
        ))
    });
    if !output.status.success() {
        fail(format!(
            "git update-ref transaction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
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

fn changed_object_ids(
    git_dir: &Path,
    expected: &[(String, String)],
    desired: &[(String, String)],
) -> Vec<String> {
    let desired_ids = desired
        .iter()
        .map(|entry| entry.1.as_str())
        .collect::<BTreeSet<_>>();
    if desired_ids.is_empty() {
        return Vec::new();
    }
    let mut command = Command::new("git");
    command
        .arg("--git-dir")
        .arg(git_dir)
        .args(["rev-list", "--objects"]);
    for oid in &desired_ids {
        command.arg(oid);
    }
    let excluded = expected
        .iter()
        .map(|entry| entry.1.as_str())
        .collect::<BTreeSet<_>>();
    if !excluded.is_empty() {
        command.arg("--not");
        for oid in excluded {
            command.arg(oid);
        }
    }
    let output = command
        .output()
        .unwrap_or_else(|error| fail(error.to_string()));
    if !output.status.success() {
        return all_object_ids(git_dir);
    }
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
    let batch_count = object_negotiation_batch_count(ids.len());
    let mut progress =
        TransferProgress::new("negotiating objects", "batches", batch_count as u64, 0);
    let calls = ids.chunks(500).map(|batch| {
        let values = batch
            .iter()
            .map(|oid| format!("\"{oid}\""))
            .collect::<Vec<_>>()
            .join(";");
        (
            "missing_objects".into(),
            format!("(principal \"{owner}\", \"{repo}\", vec {{{values}}}, {browse_only})"),
        )
    });
    for_bounded_icp_calls(canister, calls, |result| {
        missing.extend(
            result
                .get("ok")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail(format!("object negotiation rejected: {result}")))
                .iter()
                .map(|value| value.as_str().unwrap().to_owned()),
        );
        progress.advance(1);
    });
    missing
}

fn object_negotiation_batch_count(object_count: usize) -> usize {
    object_count.div_ceil(500)
}

fn can_skip_missing_object_negotiation(expected_refs: &[(String, String)]) -> bool {
    expected_refs.is_empty()
}

fn pack_segment_bytes() -> usize {
    env::var("INFINIGIT_MAX_PACK_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_PACK_SEGMENT_BYTES)
        .max(1024 * 1024)
}

fn create_incremental_packs(git_dir: &Path, ids: &[String]) -> Vec<String> {
    if ids.is_empty() {
        return Vec::new();
    }
    eprintln!(
        "infinigit: packing {} objects into segments of at most {} bytes",
        ids.len(),
        pack_segment_bytes()
    );
    let pack_dir = git_dir.join("objects/pack");
    fs::create_dir_all(&pack_dir).unwrap_or_else(|error| fail(error.to_string()));
    let base = pack_dir.join("pack");
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args([
            "pack-objects",
            "--no-reuse-delta",
            "--window=0",
            &format!("--max-pack-size={}", pack_segment_bytes()),
            base.to_str().unwrap(),
        ])
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
    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if ids.is_empty()
        || ids
            .iter()
            .any(|id| id.len() != 40 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        fail("git pack-objects returned an invalid pack id")
    }
    ids
}

fn canister_packs(canister: &str, owner: &str, repo: &str) -> BTreeMap<String, usize> {
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
            Some((
                pack.get("pack_id")?.as_str()?.to_owned(),
                json_usize(pack, "indexed_objects").unwrap_or(0),
            ))
        })
        .collect()
}

fn uploaded_chunk_indexes(begin: &Value) -> BTreeSet<usize> {
    begin
        .get("ok")
        .and_then(|value| value.get("uploaded_chunks"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            value
                .as_u64()
                .map(|number| number as usize)
                .or_else(|| value.as_str()?.replace('_', "").parse().ok())
        })
        .collect()
}

fn pending_chunk_indexes(chunk_count: usize, uploaded: &BTreeSet<usize>) -> Vec<usize> {
    (0..chunk_count)
        .filter(|index| !uploaded.contains(index))
        .collect()
}

fn upload_pack_chunks(
    canister: &str,
    owner: &str,
    repo: &str,
    pack_id: &str,
    path: &Path,
    capabilities: &TransportCapabilities,
    uploaded: &BTreeSet<usize>,
) {
    let total = fs::metadata(path)
        .unwrap_or_else(|error| fail(error.to_string()))
        .len();
    let chunk_count = total.div_ceil(CHUNK_SIZE as u64) as usize;
    let acknowledged = uploaded
        .iter()
        .filter(|index| **index < chunk_count)
        .map(|index| (total - (*index as u64 * CHUNK_SIZE as u64)).min(CHUNK_SIZE as u64))
        .sum();
    let mut progress = TransferProgress::new("uploading pack", "bytes", total, acknowledged);
    let pending = pending_chunk_indexes(chunk_count, uploaded);
    let concurrency = env::var("INFINIGIT_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(4)
                .saturating_mul(2)
        })
        .clamp(1, 16);
    let mut cursor = 0;
    let mut file = File::open(path).unwrap_or_else(|error| fail(error.to_string()));
    while cursor < pending.len() {
        let mut group = Vec::<(String, String, u64)>::new();
        while group.len() < concurrency && cursor < pending.len() {
            let mut uploads = Vec::new();
            let mut request_bytes = 0usize;
            while cursor < pending.len() && uploads.len() < capabilities.max_chunk_batch_items {
                let index = pending[cursor];
                let length =
                    ((total - index as u64 * CHUNK_SIZE as u64).min(CHUNK_SIZE as u64)) as usize;
                if !uploads.is_empty()
                    && request_bytes + length > capabilities.max_chunk_batch_bytes
                {
                    break;
                }
                let mut bytes = vec![0; length];
                file.seek(SeekFrom::Start(index as u64 * CHUNK_SIZE as u64))
                    .and_then(|_| file.read_exact(&mut bytes))
                    .unwrap_or_else(|error| {
                        fail(format!("cannot read pack chunk {index}: {error}"))
                    });
                let digest = format!("{:x}", Sha256::digest(&bytes));
                uploads.push((index, digest, bytes));
                request_bytes += length;
                cursor += 1;
            }
            let bytes = request_bytes as u64;
            if capabilities.version >= 2 && capabilities.max_chunk_batch_items > 1 {
                let values = uploads
                    .iter()
                    .map(|(index, digest, payload)| {
                        format!(
                            "record {{ index = {index}; digest = \"{digest}\"; payload = {} }}",
                            candid_blob(payload)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                group.push((
                    "put_pack_chunks".into(),
                    format!("(principal \"{owner}\", \"{repo}\", \"{pack_id}\", vec {{{values}}})"),
                    bytes,
                ));
            } else {
                let (index, digest, payload) = uploads.pop().expect("one pending chunk");
                group.push(("put_pack_chunk".into(), format!("(principal \"{owner}\", \"{repo}\", \"{pack_id}\", {index}, \"{digest}\", {})", candid_blob(&payload)), bytes));
            }
        }
        let byte_counts = group.iter().map(|entry| entry.2).collect::<Vec<_>>();
        let calls = group
            .into_iter()
            .map(|(method, argument, _)| (method, argument))
            .collect();
        let results = parallel_icp_calls(canister, calls);
        for (result, bytes) in results.into_iter().zip(byte_counts) {
            if result.get("ok").is_none() {
                fail(format!("chunk upload rejected: {result}"));
            }
            progress.advance(bytes);
        }
    }
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
    let mut timer = TransportTimer::new("push");
    let (capabilities, expected_refs, remote_packs) = take_session_snapshot(git_dir)
        .or_else(|| transport_snapshot(canister, owner, repo, git_dir))
        .map(|snapshot| (snapshot.capabilities, snapshot.refs, snapshot.packs))
        .unwrap_or_else(|| {
            std::thread::scope(|scope| {
                let capabilities = scope.spawn(|| transport_capabilities(canister));
                let refs = scope.spawn(|| canister_refs(canister, owner, repo));
                let packs = scope.spawn(|| canister_packs(canister, owner, repo));
                (
                    capabilities.join().unwrap_or_default(),
                    refs.join()
                        .unwrap_or_else(|_| fail("ref negotiation panicked")),
                    packs
                        .join()
                        .unwrap_or_else(|_| fail("pack negotiation panicked")),
                )
            })
        });
    let desired_refs = local_refs(git_dir);
    let changes = candid_ref_changes(&expected_refs, &desired_refs);
    let mut desired_pack_ids = remote_packs.keys().cloned().collect::<Vec<_>>();
    eprintln!("infinigit: scanning the local Git object graph");
    let candidates = changed_object_ids(git_dir, &expected_refs, &desired_refs);
    eprintln!("infinigit: found {} candidate objects", candidates.len());
    if candidates.is_empty() && changes.is_empty() {
        timer.mark("up_to_date");
        return;
    }
    let missing = if can_skip_missing_object_negotiation(&expected_refs) {
        eprintln!("infinigit: empty remote; all candidate objects are new");
        candidates.clone()
    } else {
        missing_objects(canister, owner, repo, &candidates, false)
    };
    timer.mark("negotiate");
    let compacted = desired_pack_ids.len() >= capabilities.max_retained_packs.saturating_sub(10);
    if compacted {
        git(git_dir, &["repack", "-a", "-d"]);
        desired_pack_ids.clear();
        let pack_dir = git_dir.join("objects/pack");
        desired_pack_ids.extend(
            fs::read_dir(pack_dir)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|value| value == "pack"))
                .map(|path| pack_id_from_file(&path).unwrap_or_else(|error| fail(error))),
        );
    } else {
        desired_pack_ids.extend(create_incremental_packs(git_dir, &missing))
    }
    desired_pack_ids.sort();
    desired_pack_ids.dedup();
    let pack_dir = git_dir.join("objects/pack");
    for id in desired_pack_ids.clone() {
        let path = pack_dir.join(format!("pack-{id}.pack"));
        let index = path.with_extension("idx");
        if remote_packs
            .get(&id)
            .zip(pack_index_object_count(&index))
            .is_some_and(|(remote, local)| *remote == local)
        {
            continue;
        }
        let objects = pack_object_metadata(git_dir, &index);
        let total_size = fs::metadata(&path)
            .unwrap_or_else(|error| fail(error.to_string()))
            .len();
        if pack_id_from_file(&path).as_deref() != Ok(id.as_str()) {
            fail(format!("local pack checksum mismatch: {id}"))
        }
        let begin = icp_json(
            canister,
            "begin_pack",
            &format!(
                "(principal \"{owner}\", \"{repo}\", \"{id}\", {}, {CHUNK_SIZE})",
                total_size
            ),
        );
        let complete = begin
            .get("ok")
            .and_then(|v| v.get("complete"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !complete {
            upload_pack_chunks(
                canister,
                owner,
                repo,
                &id,
                &path,
                &capabilities,
                &uploaded_chunk_indexes(&begin),
            );
            let result = icp_json(
                canister,
                "finalize_pack",
                &format!("(principal \"{owner}\", \"{repo}\", \"{id}\")"),
            );
            if result.get("ok").is_none() {
                fail(format!("pack finalization rejected: {result}"));
            }
        }
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
        let index_batch_size = capabilities.max_pack_index_batch_items;
        let mut batches = pending.chunks(index_batch_size);
        if capabilities.version >= 2 && already.is_empty() && !pending.is_empty() {
            let first = batches.next().unwrap_or(&[]);
            let (method, argument) = pack_index_call(&capabilities, owner, repo, &id, first, true);
            let indexed = icp_json(canister, &method, &argument);
            if indexed.get("ok").is_none() {
                fail(format!("pack index batch rejected: {indexed}"));
            }
        }
        let remaining =
            batches.map(|batch| pack_index_call(&capabilities, owner, repo, &id, batch, false));
        if capabilities.version >= 2 {
            for_bounded_icp_calls(canister, remaining, |result| {
                if result.get("ok").is_none() {
                    fail(format!("pack index batch rejected: {result}"));
                }
            });
        } else {
            for (method, argument) in remaining {
                let result = icp_json(canister, &method, &argument);
                if result.get("ok").is_none() {
                    fail(format!("pack index batch rejected: {result}"));
                }
            }
        }
    }
    timer.mark("pack_upload_and_index");

    // Browser repository views read canonical loose objects through get_object.
    // Publish those objects before moving refs so a newly visible commit can
    // never point at a tree/blob that the browser cannot load.
    let browse_candidates = if capabilities.packed_object_reads {
        non_blob_object_ids(git_dir, &candidates)
    } else {
        candidates.clone()
    };
    index_browse_objects(canister, owner, repo, git_dir, &browse_candidates);
    timer.mark("browse_objects");

    publish_ref_changes(canister, owner, repo, &changes);
    if compacted {
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
    timer.mark("publish_and_prune");
}

fn materialize(canister: &str, owner: &str, repo: &str, git_dir: &Path) {
    let mut timer = TransportTimer::new("pull");
    if !git_dir.join("HEAD").exists() {
        fs::create_dir_all(git_dir)
            .unwrap_or_else(|e| fail(format!("cannot create {}: {e}", git_dir.display())));
        run(Command::new("git").args(["init", "--bare", git_dir.to_str().unwrap()]));
    }
    let snapshot = transport_snapshot(canister, owner, repo, git_dir);
    if let Some(value) = &snapshot {
        store_session_snapshot(git_dir, value);
    }
    let (capabilities, snapshot_refs, values) = if let Some(snapshot) = snapshot {
        (
            snapshot.capabilities,
            Some(snapshot.refs),
            snapshot.pack_values,
        )
    } else {
        let capabilities_handle = std::thread::spawn({
            let canister = canister.to_owned();
            move || transport_capabilities(&canister)
        });
        let packs = icp_json(
            canister,
            "list_packs",
            &format!("(principal \"{owner}\", \"{repo}\")"),
        );
        let values = packs
            .get("ok")
            .and_then(Value::as_array)
            .unwrap_or_else(|| fail(format!("pack listing rejected: {packs}")))
            .clone();
        (capabilities_handle.join().unwrap_or_default(), None, values)
    };
    let pack_dir = git_dir.join("objects/pack");
    fs::create_dir_all(&pack_dir)
        .unwrap_or_else(|e| fail(format!("cannot create {}: {e}", pack_dir.display())));
    let mut installed_pack = false;
    for pack in &values {
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
        if pack_id_from_file(&path).as_deref() == Ok(id) {
            let index = path.with_extension("idx");
            if !index.exists() {
                git(git_dir, &["index-pack", path.to_str().unwrap()]);
            }
            continue;
        }
        let batched_downloads =
            capabilities.version >= 2 && capabilities.max_download_batch_items > 1;
        let calls = if batched_downloads {
            (0..count)
                .collect::<Vec<_>>()
                .chunks(capabilities.max_download_batch_items)
                .map(|indexes| {
                    let indexes = indexes
                        .iter()
                        .map(usize::to_string)
                        .collect::<Vec<_>>()
                        .join(";");
                    (
                        "get_pack_chunks".into(),
                        format!("(principal \"{owner}\", \"{repo}\", \"{id}\", vec {{{indexes}}})"),
                    )
                })
                .collect()
        } else {
            (0..count)
                .map(|index| {
                    (
                        "get_pack_chunk".into(),
                        format!("(principal \"{owner}\", \"{repo}\", \"{id}\", {index})"),
                    )
                })
                .collect()
        };
        let incoming = pack_dir.join(format!("pack-{id}.incoming-{}.pack", std::process::id()));
        let incoming_index = incoming.with_extension("idx");
        let mut output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&incoming)
            .unwrap_or_else(|error| fail(format!("cannot create {}: {error}", incoming.display())));
        for_parallel_icp_calls(canister, calls, |response| {
            let data = response
                .get("ok")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail(format!("chunk download rejected: {response}")));
            if batched_downloads {
                for chunk in data {
                    let chunk = chunk
                        .as_array()
                        .unwrap_or_else(|| fail("invalid chunk batch response"));
                    let bytes = chunk
                        .iter()
                        .map(|value| value.as_u64().unwrap() as u8)
                        .collect::<Vec<_>>();
                    output
                        .write_all(&bytes)
                        .unwrap_or_else(|error| fail(error.to_string()));
                }
            } else {
                let bytes = data
                    .iter()
                    .map(|value| value.as_u64().unwrap() as u8)
                    .collect::<Vec<_>>();
                output
                    .write_all(&bytes)
                    .unwrap_or_else(|error| fail(error.to_string()));
            }
        });
        drop(output);
        if pack_id_from_file(&incoming).as_deref() != Ok(id) {
            let _ = fs::remove_file(&incoming);
            fail(format!("pack checksum mismatch: {id}"));
        }
        git(git_dir, &["index-pack", incoming.to_str().unwrap()]);
        if path.exists() {
            fs::remove_file(&path)
                .unwrap_or_else(|e| fail(format!("cannot replace {}: {e}", path.display())));
        }
        let index = path.with_extension("idx");
        if index.exists() {
            let _ = fs::remove_file(&index);
        }
        fs::rename(&incoming, &path).unwrap_or_else(|error| fail(error.to_string()));
        fs::rename(&incoming_index, &index).unwrap_or_else(|error| fail(error.to_string()));
        installed_pack = true;
    }
    if values.len() > 1 && (installed_pack || !pack_dir.join("multi-pack-index").exists()) {
        git(git_dir, &["multi-pack-index", "write"]);
    }
    timer.mark("pack_download_and_verify");
    let desired_refs = snapshot_refs.unwrap_or_else(|| canister_refs(canister, owner, repo));
    let mut has_main = false;
    for (name, _) in &desired_refs {
        has_main |= name == "refs/heads/main";
    }
    replace_local_refs(git_dir, &desired_refs);
    if has_main {
        git(git_dir, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    }
    timer.mark("refs");
}

fn index_browse_objects(
    canister: &str,
    owner: &str,
    repo: &str,
    git_dir: &Path,
    object_ids: &[String],
) {
    let missing = missing_objects(canister, owner, repo, object_ids, true);
    let mut batch = Vec::<(String, String, Vec<u8>)>::new();
    let mut batch_bytes = 0usize;
    let mut calls = Vec::<(String, String)>::new();
    let concurrency = env::var("INFINIGIT_UPLOAD_CONCURRENCY")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8)
        .clamp(1, 16);
    let flush_calls = |calls: &mut Vec<(String, String)>| {
        if calls.is_empty() {
            return;
        }
        for result in parallel_icp_calls(canister, std::mem::take(calls)) {
            if result.get("ok").is_none() {
                fail(format!("browse object batch rejected: {result}"));
            }
        }
    };
    let flush = |batch: &mut Vec<(String, String, Vec<u8>)>,
                 batch_bytes: &mut usize,
                 calls: &mut Vec<(String, String)>| {
        if batch.is_empty() {
            return;
        }
        let objects = batch.iter().map(|(oid, kind, payload)| format!("record {{ oid = \"{oid}\"; git_object = record {{ kind = variant {{ \"{kind}\" }}; payload = {} }} }}", candid_blob(payload))).collect::<Vec<_>>().join(";");
        calls.push((
            "put_objects_batch".into(),
            format!("(principal \"{owner}\", \"{repo}\", vec {{{objects}}})"),
        ));
        batch.clear();
        *batch_bytes = 0;
    };
    let mut completed = 0u64;
    let mut progress = TransferProgress::new(
        "publishing browser objects",
        "objects",
        missing.len() as u64,
        0,
    );
    for_each_git_object(git_dir, &missing, |oid, kind, payload| {
        if should_inline_object(payload.len()) {
            if batch.len() == 100 || batch_bytes + payload.len() > 1_250_000 {
                flush(&mut batch, &mut batch_bytes, &mut calls)
            }
            batch_bytes += payload.len();
            batch.push((oid, kind, payload));
        } else {
            flush(&mut batch, &mut batch_bytes, &mut calls);
            flush_calls(&mut calls);
            index_browse_object(canister, owner, repo, &oid, &kind, &payload);
        }
        completed += 1;
        progress.advance(1);
        if calls.len() >= concurrency {
            flush_calls(&mut calls);
        }
    });
    flush(&mut batch, &mut batch_bytes, &mut calls);
    flush_calls(&mut calls);
    debug_assert_eq!(completed, missing.len() as u64);
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
        });
    for_bounded_icp_calls(canister, calls, |result| {
        if result.get("ok").is_none() {
            fail(format!("browse object chunk upload rejected: {result}"));
        }
    });
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
        "index-browse" => {
            let ids = all_object_ids(path);
            index_browse_objects(&args[2], &args[3], &args[4], path, &ids)
        }
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
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.pack");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(pack_id_from_file(&path).unwrap(), pack_id(&bytes));
    }
    #[test]
    fn selects_inline_and_chunked_object_boundaries() {
        assert!(should_inline_object(INLINE_OBJECT_LIMIT));
        assert!(!should_inline_object(INLINE_OBJECT_LIMIT + 1));
    }
    #[test]
    fn batches_binary_git_object_reads_and_atomically_replaces_refs() {
        let directory = tempfile::tempdir().unwrap();
        let git_dir = directory.path().join("repository.git");
        run(Command::new("git").args(["init", "--bare", git_dir.to_str().unwrap()]));
        let first = directory.path().join("first.bin");
        let second = directory.path().join("second.bin");
        fs::write(&first, [0, b'\n', 255]).unwrap();
        fs::write(&second, b"second\n").unwrap();
        let first_oid = String::from_utf8_lossy(
            &git(&git_dir, &["hash-object", "-w", first.to_str().unwrap()]).stdout,
        )
        .trim()
        .to_owned();
        let second_oid = String::from_utf8_lossy(
            &git(&git_dir, &["hash-object", "-w", second.to_str().unwrap()]).stdout,
        )
        .trim()
        .to_owned();
        let objects = read_git_objects(&git_dir, &[first_oid.clone(), second_oid.clone()]);
        assert_eq!(
            objects[0],
            (first_oid.clone(), "blob".into(), vec![0, b'\n', 255])
        );
        assert_eq!(
            objects[1],
            (second_oid.clone(), "blob".into(), b"second\n".to_vec())
        );

        replace_local_refs(&git_dir, &[("refs/tags/main".into(), first_oid.clone())]);
        replace_local_refs(&git_dir, &[("refs/tags/next".into(), second_oid.clone())]);
        assert_eq!(
            local_refs(&git_dir),
            vec![("refs/tags/next".into(), second_oid)]
        );
    }

    #[test]
    fn large_cat_file_batches_drain_output_while_feeding_input() {
        let directory = tempfile::tempdir().unwrap();
        let git_dir = directory.path().join("repository.git");
        run(Command::new("git").args(["init", "--bare", git_dir.to_str().unwrap()]));
        let fixture = directory.path().join("fixture.txt");
        fs::write(&fixture, b"pipe deadlock regression\n").unwrap();
        let oid = String::from_utf8_lossy(
            &git(&git_dir, &["hash-object", "-w", fixture.to_str().unwrap()]).stdout,
        )
        .trim()
        .to_owned();
        let ids = vec![oid; 20_000];

        let mut seen = 0;
        for_each_git_object(&git_dir, &ids, |_, kind, payload| {
            assert_eq!(kind, "blob");
            assert_eq!(payload, b"pipe deadlock regression\n");
            seen += 1;
        });
        assert_eq!(seen, ids.len());
        assert!(non_blob_object_ids(&git_dir, &ids).is_empty());
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
            "transport_capabilities",
            "transport_snapshot",
            "put_pack_chunks",
            "finalize_pack",
            "list_pack_objects",
            "index_pack_objects_batch",
            "index_pack_objects_batch_v2",
            "index_pack_objects_batch_v3",
            "put_objects_batch",
            "update_refs_atomic",
            "stage_ref_transaction_page",
            "commit_ref_transaction",
            "abort_ref_transaction",
            "prune_packs",
            "get_pack_chunk",
            "get_pack_chunks",
            "begin_chunked_object",
            "put_object_chunk",
            "finalize_chunked_object",
        ] {
            assert!(env.get_method(&actor, method).is_ok(), "missing {method}");
        }
    }

    #[test]
    fn resumes_only_unacknowledged_pack_chunks() {
        let receipt = serde_json::json!({
            "ok": { "uploaded_chunks": ["0", 2, "4_000"] }
        });
        assert_eq!(
            uploaded_chunk_indexes(&receipt),
            BTreeSet::from([0, 2, 4_000])
        );
        assert_eq!(
            pending_chunk_indexes(5, &BTreeSet::from([0, 2, 4_000])),
            vec![1, 3, 4]
        );
        assert!(uploaded_chunk_indexes(&serde_json::json!({"err": "missing"})).is_empty());
    }

    #[test]
    fn initial_push_skips_unnecessary_per_object_remote_negotiation() {
        assert!(can_skip_missing_object_negotiation(&[]));
        assert!(!can_skip_missing_object_negotiation(&[(
            "refs/heads/main".into(),
            "ab".repeat(20),
        )]));
        assert_eq!(object_negotiation_batch_count(0), 0);
        assert_eq!(object_negotiation_batch_count(1_000_001), 2_001);
    }

    #[test]
    fn retries_only_idempotent_transport_operations() {
        for method in [
            "begin_pack",
            "put_pack_chunks",
            "finalize_pack",
            "index_pack_objects_batch_v3",
            "put_objects_batch",
            "get_pack_chunks",
        ] {
            assert!(retryable_method(method), "{method} should be retryable");
        }
        for method in [
            "update_refs_atomic",
            "stage_ref_transaction_page",
            "commit_ref_transaction",
            "abort_ref_transaction",
        ] {
            assert!(
                !retryable_method(method),
                "{method} must not be blindly retried"
            );
        }
    }

    #[test]
    fn v4_pack_indexes_include_verified_ranges_while_old_shards_stay_compatible() {
        let object = PackObjectMetadata {
            oid: "ab".repeat(20),
            kind: "blob".into(),
            size: 42,
            offset: 123,
            packed_length: 17,
        };
        let mut capabilities = TransportCapabilities::default();
        capabilities.version = 4;
        let (method, argument) = pack_index_call(
            &capabilities,
            "aaaaa-aa",
            "repo",
            &"cd".repeat(20),
            &[&object],
            true,
        );
        assert_eq!(method, "index_pack_objects_batch_v3");
        assert!(argument.contains("offset = 123"));
        assert!(argument.contains("packed_length = 17"));

        capabilities.version = 2;
        let (method, argument) = pack_index_call(
            &capabilities,
            "aaaaa-aa",
            "repo",
            &"cd".repeat(20),
            &[&object],
            false,
        );
        assert_eq!(method, "index_pack_objects_batch_v2");
        assert!(!argument.contains("packed_length"));

        capabilities.version = 1;
        assert_eq!(
            pack_index_call(
                &capabilities,
                "aaaaa-aa",
                "repo",
                &"cd".repeat(20),
                &[&object],
                false,
            )
            .0,
            "index_pack_objects_batch"
        );
    }

    #[test]
    fn progress_is_bounded_and_accounts_for_resumed_bytes() {
        let mut progress = TransferProgress::new("test", "bytes", 100, 60);
        progress.advance(25);
        assert_eq!(progress.completed, 85);
        progress.advance(100);
        assert_eq!(progress.completed, 100);
    }
}
