//! `orange snapshot export|verify|import` (spec 22 §6–§7), and the trust a
//! verifier is given.
//!
//! `orange snapshot export --data-dir <dir> --out <file> [--epoch <n>]` writes
//! the snapshot of an epoch (the latest recorded, by default) from a stopped
//! node's data directory: its chain store and its driver tables.
//! `orange snapshot verify --snapshot <file> --genesis <genesis.json>
//! [--trust-key <id>:<0x 96 bytes> | <0x 96 bytes>]` checks a file and prints what it holds.
//! `orange snapshot import --snapshot <file> --data-dir <dir> --kernel <kernel>
//! --genesis <genesis.json> [--trust-key <0x 96 bytes>]` verifies it and
//! loads it into a fresh data directory, which `orange node --data-dir <dir>`
//! then starts from; `orange node --snapshot <file>` does both in one go.
//!
//! `orange snapshot trust-key --rpc <addr,...>` prints the active key set
//! that every node named reports, as `<id>:<0x group key>`, for
//! `--trust-key`.
//!
//! The trust: `--trust-key` names a key set of the chain's threshold key
//! (spec 15 §6) by id and group key, from which a node that syncs from its
//! peers follows the chain's handoffs to the snapshot's key set within the
//! key set's horizon (spec 22 §7.5), or a bare group key, which a threshold
//! certificate must verify under; without it the genesis validator set is
//! trusted, and the certificate must be
//! that set's votes. Only a chain without staking keeps its genesis set for
//! good, so a chain with staking needs `--trust-key`: validators that have
//! since left could otherwise sign a history of their own.

use std::path::Path;

use orange_abi::Decode;
use orange_abi::chain::{GenesisParams, ValidatorSet};
use orange_abi::types::Genesis;
use orange_node::{Node, NodeConfig, StoreConfig};
use orange_store::{KeyChain, Snapshot, Trust};

use crate::{arg, load_kernel, parse_genesis, parse_number};

/// The trust `--trust-key` names, or the genesis set without it on a
/// chain without staking.
///
/// # Errors
/// A message when the key is not 96 bytes of hex, or the key set's id not a
/// number, when a key set is named on a chain without a threshold key, when
/// the key is missing on a chain with staking, or when the genesis set does
/// not decode.
pub fn trust(args: &[String], genesis: &Genesis) -> Result<Trust, String> {
    let key = |hex: &str| {
        orange_rpc::methods::parse_hex(hex)
            .ok()
            .and_then(|b| <[u8; 96]>::try_from(b).ok())
            .ok_or_else(|| {
                "--trust-key must be 96 bytes of 0x hex, or <key set id>:<them>".to_owned()
            })
    };
    match arg(args, "--trust-key") {
        Some(text) => match text.split_once(':') {
            None => key(&text).map(Trust::Key),
            Some((id, hex)) => {
                let id: u64 = id
                    .parse()
                    .map_err(|_| format!("--trust-key: {id} is not a key set id"))?;
                let staking = GenesisParams::from_bytes(&genesis.params)
                    .map(|p| p.staking)
                    .unwrap_or_default();
                if staking.epoch_blocks == 0 || staking.dkg_phase_blocks == 0 {
                    return Err(
                        "--trust-key names a key set, and this chain has no threshold key"
                            .to_owned(),
                    );
                }
                Ok(Trust::KeySet(KeyChain::new(
                    id,
                    key(hex)?,
                    staking.unbonding_epochs,
                )))
            }
        },
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
        orange_rpc::methods::data(&h.state_root),
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
    let store = orange_store::DiskStore::open(dir)
        .map_err(|e| format!("{}: {e} (is the node still running?)", dir.display()))?;
    let mut driver =
        orange_node::DriverStore::open(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
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
    let head = node.chain_store().map_or(0, orange_store::DiskStore::head);
    if head != 0 {
        return Err(format!(
            "the data directory already holds chain state at height {head}; a snapshot loads into an empty one"
        ));
    }
    node.import_snapshot(snapshot).map_err(|e| e.to_string())
}

/// What a state-sync event says, for the operator.
#[must_use]
pub fn describe_event(event: &orange_node::statesync::SyncEvent) -> String {
    use orange_node::statesync::SyncEvent;
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
            orange_rpc::methods::data(peer)
        ),
        SyncEvent::PastHorizon { epoch, horizon } => format!(
            "epoch {epoch} offered, past the trusted key set's horizon (epoch {horizon}): not fetched; trust a newer key set to fetch it"
        ),
        SyncEvent::Followed { handoffs, key_set } => {
            format!("{handoffs} handoffs verified, reaching key set {key_set}")
        }
        SyncEvent::Banned { peer, why } => format!(
            "peer {} no longer asked: {why}",
            orange_rpc::methods::data(peer)
        ),
    }
}

/// Why a state sync stopped, if it did: its own failure, or the transport's
/// reason for want of peers (spec 09 §6) with what the sync's trust says of
/// the snapshots they offered, if anything (spec 22 §7.5).
pub fn stopped<'a>(
    failed: Option<&'a str>,
    stalled: &dyn Fn() -> Option<&'a str>,
    hint: &dyn Fn() -> Option<String>,
) -> Option<String> {
    let why = failed.or_else(stalled)?;
    let hint = if failed.is_some() { None } else { hint() };
    Some(match hint {
        Some(hint) => format!("state sync: {why}: {hint}"),
        None => format!("state sync: {why}"),
    })
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
    config: orange_node::statesync::SyncConfig,
    transport: &mut orange_node::Transport,
    now: &dyn Fn() -> u64,
) -> Result<Snapshot, String> {
    use orange_node::statesync::StateSync;
    let dir = config.dir.clone();
    let mut sync = StateSync::new(config).map_err(|e| format!("{}: {e}", dir.display()))?;
    eprintln!("state sync: asking peers for snapshots");
    loop {
        transport.poll_sync(&mut sync, now());
        for event in sync.take_events() {
            eprintln!("state sync: {}", describe_event(&event));
        }
        let stall = || transport.sync_stalled(now());
        if let Some(why) = stopped(sync.failed(), &stall, &|| sync.hint()) {
            return Err(why);
        }
        if let Some(snapshot) = sync.done() {
            return Ok(snapshot.clone());
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// `orange snapshot trust-key --rpc <addr,...>`: the group key of the active
/// key set (`orange_getGroupKey`, spec 17 §7) that every node named reports,
/// for `--trust-key`. Nodes that disagree, as they may for a moment around
/// a key handoff, or one that reports none, fail the command with what
/// each said, so that one node alone never decides what a joiner trusts
/// unless it is the only one named.
fn trust_key(args: &[String]) -> Result<String, String> {
    let list = arg(args, "--rpc").ok_or("--rpc <addr,...> is required")?;
    let mut keys = Vec::new();
    for rpc in list.split(',').map(str::trim).filter(|a| !a.is_empty()) {
        let answer = crate::client::call(rpc, "orange_getGroupKey", &serde_json::json!([]))?;
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
    let (_, key, key_id) = &keys[0];
    let key_id = crate::client::quantity(key_id).map_err(|e| format!("{}: {e}", keys[0].0))?;
    Ok(format!("{key_id}:{key}"))
}

/// Runs `orange snapshot <subcommand>` and returns what it prints.
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
