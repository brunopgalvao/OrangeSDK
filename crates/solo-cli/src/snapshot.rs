//! `solo snapshot export|verify|import` (spec 22 §6–§7), and the trust a
//! verifier is given.
//!
//! `solo snapshot export --data-dir <dir> --out <file> [--epoch <n>]` writes
//! the snapshot of an epoch (the latest recorded, by default) from a stopped
//! node's data directory: its chain store and its driver tables.
//! `solo snapshot verify --snapshot <file> --genesis <genesis.json>
//! [--trust-key <0x 96 bytes>]` checks a file and prints what it holds.
//! `solo snapshot import --snapshot <file> --data-dir <dir> --kernel <kernel>
//! --genesis <genesis.json> [--trust-key <0x 96 bytes>]` verifies it and
//! loads it into a fresh data directory, which `solo node --data-dir <dir>`
//! then starts from; `solo node --snapshot <file>` does both in one go.
//!
//! `solo snapshot trust-key --rpc <addr,...>` prints the group key of the
//! active key set that every node named reports, for `--trust-key`.
//!
//! The trust: `--trust-key` names a group key of the chain's threshold key
//! (spec 15 §6), which a threshold certificate must verify under; without
//! it the genesis validator set is trusted, and the certificate must be
//! that set's votes. Only a chain without staking keeps its genesis set for
//! good, so a chain with staking needs `--trust-key`: validators that have
//! since left could otherwise sign a history of their own.

use std::path::Path;

use solo_abi::Decode;
use solo_abi::chain::{GenesisParams, ValidatorSet};
use solo_abi::types::Genesis;
use solo_node::{Node, NodeConfig, StoreConfig};
use solo_store::{Snapshot, Trust};

use crate::{arg, load_kernel, parse_genesis, parse_number};

/// The trust `--trust-key` names, or the genesis set without it on a
/// chain without staking.
///
/// # Errors
/// A message when the key is not 96 bytes of hex, when it is missing on a
/// chain with staking, or when the genesis set does not decode.
pub fn trust(args: &[String], genesis: &Genesis) -> Result<Trust, String> {
    match arg(args, "--trust-key") {
        Some(hex) => solo_rpc::methods::parse_hex(&hex)
            .ok()
            .and_then(|b| <[u8; 96]>::try_from(b).ok())
            .map(Trust::Key)
            .ok_or_else(|| "--trust-key must be 96 bytes of 0x hex".to_owned()),
        None if GenesisParams::from_bytes(&genesis.params)
            .is_ok_and(|p| p.staking.epoch_blocks != 0) =>
        {
            Err(
                "a chain with staking needs --trust-key: its genesis set is not its set for good"
                    .to_owned(),
            )
        }
        // A genesis file always names a set that decodes (parse_genesis
        // builds it); a genesis from elsewhere may not.
        None => ValidatorSet::from_bytes(&genesis.validators)
            .ok()
            .map(Trust::Genesis)
            .ok_or("genesis: validators do not decode".to_owned()),
    }
}

/// Reads the genesis file `--genesis` names.
fn genesis_argument(args: &[String]) -> Result<Genesis, String> {
    let path = arg(args, "--genesis").ok_or("--genesis is required")?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    parse_genesis(&text)
}

/// Reads the snapshot file `--snapshot` names.
fn snapshot_argument(args: &[String]) -> Result<Snapshot, String> {
    let path = arg(args, "--snapshot").ok_or("--snapshot is required")?;
    Snapshot::open(Path::new(&path)).map_err(|e| format!("{path}: {e}"))
}

/// What a verified snapshot holds, one line per fact.
#[must_use]
pub fn describe(snapshot: &Snapshot) -> String {
    let h = &snapshot.header;
    format!(
        "snapshot of chain {} at epoch {}: block {}, state root {}, {} entries, {} certificate",
        h.chain_id,
        h.epoch,
        h.height,
        solo_rpc::methods::data(&h.state_root),
        h.entries,
        if h.certificate.len() == 97 {
            "threshold"
        } else {
            "vote"
        },
    )
}

/// Verifies `snapshot` for the chain of `genesis` under the trust `args` name.
///
/// # Errors
/// Why it does not verify.
pub fn verify(args: &[String], snapshot: &Snapshot, genesis: &Genesis) -> Result<(), String> {
    let trust = trust(args, genesis)?;
    snapshot
        .verify(genesis.chain_id, &trust)
        .map_err(|e| e.to_string())
}

fn export(args: &[String]) -> Result<String, String> {
    let dir = arg(args, "--data-dir").ok_or("--data-dir is required")?;
    let out = arg(args, "--out").ok_or("--out is required")?;
    let epoch = parse_number(args, "--epoch")?;
    let dir = Path::new(&dir);
    let store = solo_store::DiskStore::open(dir)
        .map_err(|e| format!("{}: {e} (is the node still running?)", dir.display()))?;
    let mut driver =
        solo_node::DriverStore::open(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let (tables, _) = driver.take_loaded();
    let snapshot = Snapshot::export(&store, &tables, epoch, Path::new(&out))
        .map_err(|e| format!("{out}: {e}"))?;
    Ok(format!("{} written to {out}", describe(&snapshot)))
}

fn verify_command(args: &[String]) -> Result<String, String> {
    let genesis = genesis_argument(args)?;
    let snapshot = snapshot_argument(args)?;
    verify(args, &snapshot, &genesis)?;
    Ok(format!("{} verifies", describe(&snapshot)))
}

fn import(args: &[String]) -> Result<String, String> {
    let genesis = genesis_argument(args)?;
    let snapshot = snapshot_argument(args)?;
    verify(args, &snapshot, &genesis)?;
    let kernel = load_kernel(&arg(args, "--kernel").ok_or("--kernel is required")?)?;
    let dir = arg(args, "--data-dir").ok_or("--data-dir is required")?;
    let config = NodeConfig {
        store: StoreConfig::Disk(dir.clone().into()),
        ..NodeConfig::default()
    };
    let mut node = Node::open(&kernel, &genesis, config).map_err(|e| e.to_string())?;
    import_into(&mut node, &snapshot)?;
    Ok(format!("{} imported into {dir}", describe(&snapshot)))
}

/// Loads a verified `snapshot` into `node`, which must hold the genesis
/// alone: a node whose store already holds a chain keeps it.
///
/// # Errors
/// A message when the store holds more than the genesis, or the import fails.
pub fn import_into(node: &mut Node, snapshot: &Snapshot) -> Result<(), String> {
    let head = node.chain_store().map_or(0, solo_store::DiskStore::head);
    if head != 0 {
        return Err(format!(
            "the data directory already holds chain state at height {head}; a snapshot loads into an empty one"
        ));
    }
    node.import_snapshot(snapshot).map_err(|e| e.to_string())
}

/// What a state-sync event says, for the operator.
#[must_use]
pub fn describe_event(event: &solo_node::statesync::SyncEvent) -> String {
    use solo_node::statesync::SyncEvent;
    match event {
        SyncEvent::Target(offer) => format!(
            "fetching epoch {} (block {}, {} entries)",
            offer.epoch, offer.height, offer.entries
        ),
        SyncEvent::Resumed { slices } => {
            format!("{slices} slices verified by an earlier run kept")
        }
        SyncEvent::SetAside { peer, epoch } => format!(
            "epoch {epoch} set aside: its certificate from peer {} is not the trusted key's; waiting for a newer snapshot",
            solo_rpc::methods::data(peer)
        ),
        SyncEvent::Banned { peer, why } => format!(
            "peer {} no longer asked: {why}",
            solo_rpc::methods::data(peer)
        ),
    }
}

/// Fetches a snapshot from the peers `transport` connects to, before the
/// node's driver starts (spec 22 §7.4): verified under `config`'s trust,
/// slice by slice, resuming what an earlier run in the same directory
/// verified. Polls until the snapshot file is assembled, saying what happens
/// on the way; `now` is the clock. The caller imports it.
///
/// # Errors
/// Why the sync stopped.
pub fn sync_from_peers(
    config: solo_node::statesync::SyncConfig,
    transport: &mut solo_node::Transport,
    now: &dyn Fn() -> u64,
) -> Result<Snapshot, String> {
    use solo_node::statesync::StateSync;
    let dir = config.dir.clone();
    let mut sync = StateSync::new(config).map_err(|e| format!("{}: {e}", dir.display()))?;
    eprintln!("state sync: asking peers for snapshots");
    loop {
        transport.poll_sync(&mut sync, now());
        for event in sync.take_events() {
            eprintln!("state sync: {}", describe_event(&event));
        }
        if let Some(why) = sync.failed().or_else(|| transport.sync_stalled(now())) {
            return Err(format!("state sync: {why}"));
        }
        if let Some(snapshot) = sync.done() {
            return Ok(snapshot.clone());
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// `solo snapshot trust-key --rpc <addr,...>`: the group key of the active
/// key set (`solo_getGroupKey`, spec 17 §7) that every node named reports,
/// for `--trust-key`. Nodes that disagree, as they may for a moment around
/// a key handoff, or one that reports none, fail the command with what
/// each said, so that one node alone never decides what a joiner trusts
/// unless it is the only one named.
fn trust_key(args: &[String]) -> Result<String, String> {
    let list = arg(args, "--rpc").ok_or("--rpc <addr,...> is required")?;
    let mut keys = Vec::new();
    for rpc in list.split(',').map(str::trim).filter(|a| !a.is_empty()) {
        let answer = crate::client::call(rpc, "solo_getGroupKey", &serde_json::json!([]))?;
        let key = answer["groupKey"]
            .as_str()
            .ok_or_else(|| format!("{rpc}: the chain has adopted no threshold key yet"))?;
        keys.push((rpc.to_owned(), key.to_owned(), answer["keyId"].clone()));
    }
    let (_, first, _) = keys.first().ok_or("--rpc names no node")?;
    if keys.iter().any(|(_, key, _)| key != first) {
        let said: Vec<String> = keys
            .iter()
            .map(|(rpc, key, id)| format!("{rpc}: key set {id} {}", &key[..18]))
            .collect();
        return Err(format!(
            "the nodes report different keys; ask again: {}",
            said.join(", ")
        ));
    }
    Ok(first.clone())
}

/// Runs `solo snapshot <subcommand>` and returns what it prints.
///
/// # Errors
/// A message naming the first problem.
pub fn run(args: &[String]) -> Result<String, String> {
    match args.get(2).map_or("", String::as_str) {
        "export" => export(args),
        "verify" => verify_command(args),
        "import" => import(args),
        "trust-key" => trust_key(args),
        _ => Err(crate::USAGE.to_owned()),
    }
}
