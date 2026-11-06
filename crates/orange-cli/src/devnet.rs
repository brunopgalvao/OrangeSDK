//! `orange devnet`: a network of validator processes on one machine, with the
//! staking, epochs and threshold keys of spec 15 on, governed kernel
//! upgrades and feature gates of spec 13 on, and the bridges off; the
//! tooling to watch it; and the primitives a rehearsal of a kernel upgrade
//! needs (`tools/rehearse-upgrade.sh`).
//!
//! ```text
//! orange devnet init --dir <dir> --kernel <kernel.elf|kernel.orange> [--validators 4] [--chain-id 1337]
//!                  [--slot-ms 400] [--epoch-blocks 20] [--dkg-phase-blocks 5] [--upgrade-delay 2]
//!                  [--host 127.0.0.1] [--p2p-port 30301] [--rpc-port 8545] [--seed <64 hex>]
//!                  [--governance-key <64 hex>] [--genesis-time <unix seconds>] [--force]
//! orange devnet up --dir <dir> [--blocks <n>]
//! orange devnet down --dir <dir>
//! orange devnet stop|start --dir <dir> --node <i>
//! orange devnet status (--dir <dir> | --rpc <addr,...>) [--json]
//! orange devnet wait (--dir <dir> | --rpc <addr,...>) [--nodes <i,...>] [--timeout <s>] <conditions>
//! orange devnet node --dir <dir> --index <i> [orange node options]
//! ```
//!
//! `init` derives the validator keys and the governance key from a seed
//! (random unless `--seed` is given, so a devnet is reproducible when it
//! has to be), recompiles the kernel once into `<dir>/kernel.orange`, writes
//! `<dir>/genesis.json`, `<dir>/governance.key`, one `<dir>/node-<i>/key`
//! per validator and the manifest `<dir>/devnet.json`: each node's
//! peer-to-peer and JSON-RPC addresses (port 0 picks free ports) and its
//! bootstrap addresses, every other node's: each node runs peer exchange
//! (spec 09 §5a) and dials them with backoff (a manifest of an earlier
//! devnet may still name `peers`, which a node keeps dialling). The genesis
//! carries the time of the `init` as its `timestamp`, or `--genesis-time` (spec 20
//! §3.4): the genesis block's timestamp, before which nobody makes a
//! block, so a devnet started late begins at once. The genesis runs the fee
//! market at the production defaults (spec 23 §2.1) and funds the account
//! of the README's key `0x01…01`, every validator's account and the
//! governance account, so that validators pay for their gate signals and
//! the governance key for its upgrades at the base fee. A second `init`
//! leaves an initialized directory alone unless `--force`.
//!
//! `up` starts every node as an `orange devnet node` process, its output in
//! `<dir>/node-<i>/log` and its pid in `<dir>/node-<i>/pid`, and waits for
//! them; with `--blocks` it stops them once every node has executed that
//! many blocks. `down` stops every node, `stop` and `start` one: through
//! `orange_stop`, or by signalling the pid in `node-<i>/pid` when the node
//! does not answer, and a fresh process. A node keeps its driver state in
//! `node-<i>` (`driver.state` and `persist.log`, [`orange_node::DriverStore`]),
//! so a restarted node resumes the view it left and never votes twice in
//! it, re-executes the chain it had finalized from its own tables and syncs
//! what it lacks from its peers (spec 08 §7). `status` prints one line per
//! node from `GET /status`.
//! `wait` polls until every selected node meets every condition given, or
//! the timeout passes (default 600 s):
//!
//! - `--head <n>`, `--finalized <n>`, `--peers <n>`: at least that;
//! - `--kernel-version <v>`: at least that; `--kernel-hash <0x…>`: exactly that;
//! - `--active-gates <g,…>`: those gates active for the next block;
//! - `--signalled <g,…>`: every validator's latest signal names exactly those gates;
//! - `--locked-in <g,…>`: those gates locked in (spec 13 §8.4);
//! - `--certified <n> --above <h>`: at least `n` finalized heights above `h`,
//!   among the latest 64, carry a threshold certificate (spec 12 §7);
//! - `--caught-up`: finalized within two blocks of the furthest node, of
//!   all of them, whichever `--nodes` selects;
//! - `--no-equivocations`: the node has recorded no equivocation (the
//!   driver's `equivocations` counter in its metrics, spec 08 §9).
//!
//! `status` and `wait` take `--rpc <addr,...>` instead of `--dir` for nodes
//! that run elsewhere, such as the compose stack in `ops/`.
//!
//! A *lifeline* keeps nodes from outliving whoever runs them: when
//! [`LIFELINE`] (`ORANGE_DEVNET_LIFELINE`) names a pid, `orange devnet node`
//! stops, and `up` stops waiting and fails, within a second or so of that
//! process going away, however it went. `up` gives its own nodes its own
//! pid as their lifeline, so they go down with it; `start` passes on the
//! lifeline it was given, if any, and its node otherwise runs until stopped.
//! A test or script that starts nodes sets the variable to its own pid, so
//! that nothing of its own is left running when it is killed.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use orange_host::hash::keccak256;
use orange_metrics::Status;
use orange_rpc::methods::data;
use serde_json::{Value, json};

use crate::ceremony::Operator;
use crate::client::{self, poll_until};
use crate::upgrade::parse_gates;
use crate::{CliError, arg, load_kernel, parse_genesis, parse_key};

/// The manifest `init` writes and the other subcommands read.
pub const MANIFEST: &str = "devnet.json";

/// The account the devnet genesis funds: the README's key `0x01…01`.
pub const FUNDED: &str = "0x1a642f0e3c3af545e7acbd38b07251b3990914f1";

/// Its balance, in wei: one million ether.
pub const FUNDING: &str = "1000000000000000000000000";

/// What each validator's account and the governance account hold at
/// genesis, in wei: a thousand ether, for their signals and upgrades at the
/// base fee (spec 23).
pub const OPERATOR_FUNDING: &str = "1000000000000000000000";

/// How long `start` waits for a node to answer, and `stop` for it to go.
pub const NODE_TIMEOUT: Duration = Duration::from_mins(2);

/// The environment variable naming a devnet process's lifeline: a pid
/// whose end ends it (see the module documentation).
pub const LIFELINE: &str = "ORANGE_DEVNET_LIFELINE";

/// The process [`LIFELINE`] names, checked at most once a second.
struct Lifeline {
    pid: Option<u32>,
    checked: Instant,
}

impl Lifeline {
    fn from_env() -> Lifeline {
        Lifeline {
            pid: std::env::var(LIFELINE).ok().and_then(|v| v.parse().ok()),
            checked: Instant::now(),
        }
    }

    /// Whether the lifeline still holds: no lifeline, a check less than a
    /// second ago, or its process alive. Says so on stderr when it broke.
    fn holds(&mut self) -> bool {
        let Some(pid) = self.pid else {
            return true;
        };
        if self.checked.elapsed() < Duration::from_secs(1) {
            return true;
        }
        self.checked = Instant::now();
        let holds = alive(pid);
        if !holds {
            eprintln!("devnet: lifeline {pid} is gone; stopping");
        }
        holds
    }
}

/// One node of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    /// Validator id, `0x` hex.
    pub validator: String,
    /// Peer-to-peer listen address.
    pub listen: String,
    /// JSON-RPC address.
    pub rpc: String,
    /// Peers it dials and keeps dialling (`--peer`).
    pub peers: Vec<String>,
    /// Bootstrap addresses of its peer exchange (`--bootstrap`).
    pub bootstrap: Vec<String>,
}

/// A devnet directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devnet {
    /// The directory.
    pub dir: PathBuf,
    /// Chain id.
    pub chain_id: u64,
    /// The nodes, validator `i` in `node-<i>`.
    pub nodes: Vec<NodeSpec>,
}

fn io(path: &Path, e: &std::io::Error) -> String {
    format!("{}: {e}", path.display())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|e| io(path, &e))
}

/// Writes a key file that its owner alone can read.
pub(crate) fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    // The mode applies to a file being created: an old one goes first.
    let _ = fs::remove_file(path);
    let mut options = File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let written = options
        .open(path)
        .and_then(|mut file| file.write_all(bytes));
    written.map_err(|e| io(path, &e))
}

fn text_of(v: &Value, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{MANIFEST}: {key} missing"))
}

impl Devnet {
    /// Reads the manifest of `dir`.
    ///
    /// # Errors
    /// If the manifest is missing or malformed.
    pub fn load(dir: &Path) -> Result<Devnet, String> {
        let path = dir.join(MANIFEST);
        let text = fs::read_to_string(&path).map_err(|e| io(&path, &e))?;
        let v: Value = serde_json::from_str(&text)
            .ok()
            .ok_or_else(|| format!("{}: not valid JSON", path.display()))?;
        let mut nodes = Vec::new();
        for node in v
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{MANIFEST}: nodes missing"))?
        {
            let list = |key: &str| -> Vec<String> {
                node.get(key)
                    .and_then(Value::as_array)
                    .map(|p| {
                        p.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            nodes.push(NodeSpec {
                validator: text_of(node, "validator")?,
                listen: text_of(node, "listen")?,
                rpc: text_of(node, "rpc")?,
                peers: list("peers"),
                bootstrap: list("bootstrap"),
            });
        }
        Ok(Devnet {
            dir: dir.to_path_buf(),
            chain_id: v.get("chainId").and_then(Value::as_u64).unwrap_or(0),
            nodes,
        })
    }

    /// `<dir>/kernel.orange`, the recompiled kernel every node starts from.
    #[must_use]
    pub fn kernel(&self) -> PathBuf {
        self.dir.join("kernel.orange")
    }

    /// `<dir>/genesis.json`.
    #[must_use]
    pub fn genesis(&self) -> PathBuf {
        self.dir.join("genesis.json")
    }

    /// `<dir>/governance.key`: the governance account's key, hex.
    #[must_use]
    pub fn governance_key(&self) -> PathBuf {
        self.dir.join("governance.key")
    }

    /// `<dir>/node-<i>`.
    #[must_use]
    pub fn node_dir(&self, index: usize) -> PathBuf {
        self.dir.join(format!("node-{index}"))
    }

    /// Node `index`.
    ///
    /// # Errors
    /// If there is no such node.
    pub fn node(&self, index: usize) -> Result<&NodeSpec, String> {
        self.nodes
            .get(index)
            .ok_or_else(|| format!("no node {index}: the devnet has {} nodes", self.nodes.len()))
    }
}

fn number(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    Ok(crate::parse_number(args, name)?.unwrap_or(default))
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn dir_argument(args: &[String]) -> Result<PathBuf, String> {
    arg(args, "--dir")
        .map(PathBuf::from)
        .ok_or_else(|| "--dir is required".to_owned())
}

fn node_argument(args: &[String]) -> Result<usize, String> {
    crate::parse_number(args, "--node")?
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| "--node <i> is required".to_owned())
}

/// A key derived from the devnet seed: `keccak256(label ‖ seed ‖ index)`.
fn derive(seed: &[u8; 32], label: &[u8], index: u64) -> SigningKey {
    let digest = keccak256(&[label, seed, &index.to_be_bytes()].concat());
    SigningKey::from_slice(&digest).expect("a hash is a scalar, bar a negligible chance")
}

/// `n` ports from `base`, or `n` free ports of `host` when `base` is 0.
fn ports(host: &str, base: u64, n: usize) -> Result<Vec<u16>, String> {
    if base != 0 {
        return (0..n)
            .map(|i| {
                u16::try_from(base + i as u64)
                    .ok()
                    .ok_or_else(|| format!("port {base} + {i} is above 65535"))
            })
            .collect();
    }
    let listeners: Vec<std::net::TcpListener> = (0..n)
        .map(|_| std::net::TcpListener::bind((host, 0)))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{host}: cannot pick a free port: {e}"))?;
    Ok(listeners
        .iter()
        .map(|l| l.local_addr().map_or(0, |a| a.port()))
        .collect())
}

/// `orange devnet init`.
#[allow(clippy::too_many_lines)]
fn init(args: &[String]) -> Result<String, String> {
    let dir = dir_argument(args)?;
    if dir.join(MANIFEST).exists() && !flag(args, "--force") {
        return Ok(format!(
            "{}: already initialized (--force starts over)",
            dir.display()
        ));
    }
    let kernel = load_kernel(&arg(args, "--kernel").ok_or("--kernel is required")?)?;
    let validators = usize::try_from(number(args, "--validators", 4)?)
        .ok()
        .filter(|n| (1..=256).contains(n))
        .ok_or("--validators must be 1 to 256")?;
    let chain_id = number(args, "--chain-id", 1337)?;
    let slot_ms = number(args, "--slot-ms", 400)?;
    let epoch_blocks = number(args, "--epoch-blocks", 20)?;
    let dkg_phase_blocks = number(args, "--dkg-phase-blocks", 5)?;
    let upgrade_delay = number(args, "--upgrade-delay", 2)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let genesis_time = number(args, "--genesis-time", now)?;
    let host = arg(args, "--host").unwrap_or_else(|| "127.0.0.1".to_owned());
    let seed: [u8; 32] = if let Some(hex) = arg(args, "--seed") {
        parse_key(&hex)?.to_bytes().into()
    } else {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .ok()
            .ok_or("init: the operating system gave no randomness")?;
        seed
    };
    let keys: Vec<SigningKey> = (0..validators as u64)
        .map(|i| derive(&seed, b"orange devnet validator", i))
        .collect();
    let governance = match arg(args, "--governance-key") {
        Some(hex) => parse_key(&hex)?,
        None => derive(&seed, b"orange devnet governance", 0),
    };
    let p2p = ports(&host, number(args, "--p2p-port", 30301)?, validators)?;
    let rpc = ports(&host, number(args, "--rpc-port", 8545)?, validators)?;
    let ids: Vec<String> = keys
        .iter()
        .map(|k| data(&orange_node::validator_id(k)))
        .collect();
    // The template of a ceremony (see `crate::ceremony`), its operators the
    // devnet's validators, in node order.
    let mut template = json!({
        "chainId": chain_id,
        "timestamp": genesis_time,
        "slotMs": slot_ms,
        "maxTxs": 64,
        "alloc": {
            FUNDED: FUNDING,
            data(&client::address(&governance)): OPERATOR_FUNDING,
        },
        "governance": data(&client::address(&governance)),
        "upgradeDelay": upgrade_delay,
        "epochBlocks": epoch_blocks,
        "fees": crate::fees::production_json(),
    });
    if epoch_blocks != 0 {
        template["staking"] = json!({
            "epochBlocks": epoch_blocks,
            "dkgPhaseBlocks": dkg_phase_blocks,
            "unbondingEpochs": 4,
            "maxKeyAge": 2,
        });
    }
    let operators: Vec<Operator> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| Operator::of_key(k, &format!("node-{i}"), None))
        .collect();
    let genesis = crate::ceremony::assemble(&template, &operators, OPERATOR_FUNDING, &[])?;
    let genesis_text = serde_json::to_string_pretty(&genesis).expect("json");
    // What the node will read, parsed as a node parses it and run through
    // `kernel_init` once, so that a genesis the kernel refuses fails here
    // with the reason, not in every node's log.
    let parsed = parse_genesis(&genesis_text)?;
    orange_node::Node::open(&kernel, &parsed, orange_node::NodeConfig::default())
        .map_err(|e| format!("the kernel refuses this genesis: {e}"))?;
    fs::create_dir_all(&dir).map_err(|e| io(&dir, &e))?;
    let devnet = Devnet {
        dir: dir.clone(),
        chain_id,
        nodes: (0..validators)
            .map(|i| NodeSpec {
                validator: ids[i].clone(),
                listen: format!("{host}:{}", p2p[i]),
                rpc: format!("{host}:{}", rpc[i]),
                peers: Vec::new(),
                bootstrap: (0..validators)
                    .filter(|j| *j != i)
                    .map(|j| format!("{host}:{}", p2p[j]))
                    .collect(),
            })
            .collect(),
    };
    write(&devnet.kernel(), &kernel)?;
    write(&devnet.genesis(), genesis_text.as_bytes())?;
    let hex = |k: &SigningKey| data(&k.to_bytes())[2..].to_owned();
    write_secret(&devnet.governance_key(), hex(&governance).as_bytes())?;
    let mut report = format!(
        "devnet initialized in {}\n  chain id {chain_id}, {validators} validators, slot {slot_ms} ms, epochs of {epoch_blocks} blocks, DKG phases of {dkg_phase_blocks} blocks, upgrade delay {upgrade_delay} blocks\n  fee market at the production defaults: base fee floor {} wei, burned\n  governance {} (key in governance.key)",
        dir.display(),
        orange_abi::fees::DEFAULT_MIN_BASE_FEE,
        data(&client::address(&governance))
    );
    let mut nodes = Vec::new();
    for (i, node) in devnet.nodes.iter().enumerate() {
        let node_dir = devnet.node_dir(i);
        // A node directory of an earlier devnet holds that chain's driver
        // state, log and pid: `--force` starts over from nothing.
        let cleared = if node_dir.exists() {
            fs::remove_dir_all(&node_dir)
        } else {
            Ok(())
        };
        cleared
            .and_then(|()| fs::create_dir_all(&node_dir))
            .map_err(|e| io(&node_dir, &e))?;
        write_secret(&node_dir.join("key"), hex(&keys[i]).as_bytes())?;
        let _ = write!(
            report,
            "\n  node {i}  p2p {}  rpc {}  validator {}",
            node.listen, node.rpc, node.validator
        );
        nodes.push(json!({
            "validator": node.validator,
            "listen": node.listen,
            "rpc": node.rpc,
            "peers": node.peers,
            "bootstrap": node.bootstrap,
        }));
    }
    let manifest = json!({"chainId": chain_id, "nodes": nodes});
    let manifest = serde_json::to_string_pretty(&manifest).expect("json");
    write(&dir.join(MANIFEST), manifest.as_bytes())?;
    Ok(report)
}

/// The `orange` binary to start nodes with: `ORANGE_BIN`, or this executable.
fn orange_binary() -> PathBuf {
    std::env::var_os("ORANGE_BIN").map_or_else(
        || std::env::current_exe().unwrap_or_default(),
        PathBuf::from,
    )
}

/// Starts node `index` as a process; its pid goes to `node-<i>/pid`, its
/// output to `node-<i>/log`. With `lifeline`, the node stops when that
/// process goes; without, it keeps the lifeline this process has, if any.
fn spawn(devnet: &Devnet, index: usize, lifeline: Option<u32>) -> Result<Child, String> {
    let node = devnet.node(index)?;
    if client::status(&node.rpc).is_ok() {
        return Err(format!("node {index} is already running on {}", node.rpc));
    }
    let node_dir = devnet.node_dir(index);
    let log_path = node_dir.join("log");
    let fail = |e: std::io::Error| io(&log_path, &e);
    let log = File::options()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(fail)?;
    let stderr = log.try_clone().map_err(fail)?;
    let binary = orange_binary();
    let mut command = Command::new(&binary);
    if let Some(pid) = lifeline {
        command.env(LIFELINE, pid.to_string());
    }
    let child = command
        .args(["devnet", "node", "--dir"])
        .arg(&devnet.dir)
        .arg("--index")
        .arg(index.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|e| format!("cannot start node {index} with {}: {e}", binary.display()))?;
    write(&node_dir.join("pid"), child.id().to_string().as_bytes())?;
    Ok(child)
}

/// Stops node `index` through `orange_stop`, or by signalling the pid in
/// `node-<i>/pid` when its RPC does not answer (a node still starting, or
/// wedged), and waits for it to go.
fn stop_node(devnet: &Devnet, index: usize) -> Result<String, String> {
    let node = devnet.node(index)?;
    let rpc = &node.rpc;
    let pid_file = devnet.node_dir(index).join("pid");
    let what = format!("node {index} did not stop");
    if client::call(rpc, "orange_stop", &json!([])).is_ok() {
        poll_until(NODE_TIMEOUT, &what, &mut || client::status(rpc).is_err())?;
        // The RPC goes first; the process holds its stores a little longer,
        // and whoever opens the directory next needs it gone.
        let pid = recorded_pid(&pid_file, index);
        poll_until(NODE_TIMEOUT, &what, &mut || !pid.is_some_and(alive))?;
        let _ = fs::remove_file(&pid_file);
        return Ok(format!("node {index} stopped"));
    }
    let Some(pid) = recorded_pid(&pid_file, index) else {
        return Ok(format!("node {index} is not running"));
    };
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    poll_until(NODE_TIMEOUT, &what, &mut || !alive(pid))?;
    let _ = fs::remove_file(&pid_file);
    Ok(format!("node {index} stopped (pid {pid} signalled)"))
}

/// The pid in `pid_file` when it names a live `orange devnet node` of index
/// `index`: a pid file left by a node that exited may name any process by
/// now, so the command line is checked first.
fn recorded_pid(pid_file: &Path, index: usize) -> Option<u32> {
    let pid: u32 = fs::read_to_string(pid_file).ok()?.trim().parse().ok()?;
    let out = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let words: Vec<&str> = line.split_whitespace().collect();
    let index = index.to_string();
    let ours = words.windows(2).any(|w| w == ["devnet", "node"])
        && words.windows(2).any(|w| w == ["--index", index.as_str()]);
    ours.then_some(pid)
}

/// Whether process `pid` exists.
fn alive(pid: u32) -> bool {
    Command::new("ps")
        .args(["-p", &pid.to_string()])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Stops every node; one line per node.
fn stop_all(devnet: &Devnet) -> Result<String, String> {
    let lines: Vec<String> = (0..devnet.nodes.len())
        .map(|i| stop_node(devnet, i))
        .collect::<Result<_, _>>()?;
    Ok(lines.join("\n"))
}

/// `orange devnet start --node <i>`: a fresh process, answering its RPC.
fn start_node(devnet: &Devnet, index: usize) -> Result<String, String> {
    let rpc = devnet.node(index)?.rpc.clone();
    // The process outlives this command; nothing waits for it.
    drop(spawn(devnet, index, None)?);
    let what = format!("node {index} did not answer on {rpc}");
    poll_until(NODE_TIMEOUT, &what, &mut || client::status(&rpc).is_ok())?;
    Ok(format!("node {index} started on {rpc}"))
}

/// `orange devnet up`.
fn up(args: &[String]) -> Result<String, String> {
    let devnet = Devnet::load(&dir_argument(args)?)?;
    let blocks = crate::parse_number(args, "--blocks")?;
    let mut children: Vec<(usize, Child, Option<std::process::ExitStatus>)> = Vec::new();
    for i in 0..devnet.nodes.len() {
        match spawn(&devnet, i, Some(std::process::id())) {
            Ok(child) => children.push((i, child, None)),
            Err(e) => {
                // Leave nothing of this command's behind: the nodes it
                // started go down; one that was already running is not its
                // to stop.
                for (j, mut child, _) in children {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = fs::remove_file(devnet.node_dir(j).join("pid"));
                }
                return Err(e);
            }
        }
    }
    eprintln!(
        "devnet: {} nodes started; `orange devnet down --dir {}` stops them",
        children.len(),
        devnet.dir.display()
    );
    let mut stopping = false;
    let mut lifeline = Lifeline::from_env();
    loop {
        // Its nodes' lifeline is this process: they follow it down.
        if !lifeline.holds() {
            return Err("devnet: up stopped by its lifeline".to_owned());
        }
        for (_, child, exit) in &mut children {
            if exit.is_none() {
                *exit = child.try_wait().ok().flatten();
            }
        }
        if children.iter().all(|(_, _, exit)| exit.is_some()) {
            break;
        }
        if !stopping
            && let Some(n) = blocks
            && devnet
                .nodes
                .iter()
                .all(|node| client::status(&node.rpc).is_ok_and(|s| s.head >= n))
        {
            stopping = true;
            eprintln!("devnet: every node has {n} blocks; stopping");
            let _ = stop_all(&devnet);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let failed: Vec<String> = children
        .iter()
        .filter_map(|(i, _, exit)| {
            exit.filter(|s| !s.success())
                .map(|s| format!("node {i} exited with {s}"))
        })
        .collect();
    if failed.is_empty() {
        Ok("devnet: every node stopped".to_owned())
    } else {
        Err(failed.join("\n"))
    }
}

/// The nodes, as `(label, rpc)`: every node (`--rpc <a,b,...>`, or the
/// manifest's), and the ones a command addresses, which `--nodes <i,...>`
/// narrows.
type Targets = (Vec<(String, String)>, Vec<(String, String)>);

fn targets(args: &[String]) -> Result<Targets, String> {
    let all: Vec<(String, String)> = match arg(args, "--rpc") {
        Some(list) => list
            .split(',')
            .filter(|a| !a.is_empty())
            .enumerate()
            .map(|(i, a)| (i.to_string(), a.trim().to_owned()))
            .collect(),
        None => Devnet::load(&dir_argument(args)?)?
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (i.to_string(), n.rpc.clone()))
            .collect(),
    };
    let Some(selected) = arg(args, "--nodes") else {
        return Ok((all.clone(), all));
    };
    let selected = selected
        .split(',')
        .map(|i| {
            all.iter()
                .find(|(label, _)| label == i.trim())
                .cloned()
                .ok_or_else(|| format!("--nodes: no node {i}"))
        })
        .collect::<Result<_, _>>()?;
    Ok((all, selected))
}

/// One node's row of `orange devnet status`.
fn row(label: &str, rpc: &str) -> Value {
    match client::status(rpc) {
        Ok(s) => json!({
            "node": label,
            "rpc": rpc,
            "up": true,
            "head": s.head,
            "finalized": s.finalized,
            "peers": s.peers,
            "kernelVersion": s.kernel_version,
            "kernelHash": data(&s.kernel_hash),
            "activeGates": orange_rpc::telemetry::gates(s.active_gates),
            "pendingUpgrade": s.pending_upgrade.as_ref().map(|p| p.activation_height),
            "upgradeAlert": s.upgrade_alert,
        }),
        Err(e) => json!({"node": label, "rpc": rpc, "up": false, "error": e}),
    }
}

fn status(args: &[String]) -> Result<String, String> {
    let rows: Vec<Value> = targets(args)?
        .1
        .iter()
        .map(|(label, rpc)| row(label, rpc))
        .collect();
    if flag(args, "--json") {
        return Ok(serde_json::to_string_pretty(&rows).expect("json"));
    }
    let lines: Vec<String> = rows
        .iter()
        .map(|r| {
            if r["up"] == true {
                format!(
                    "node {}  up    head {}  finalized {}  peers {}  kernel v{} {}  gates {}  pending {}  alert {}",
                    r["node"].as_str().unwrap_or_default(),
                    r["head"],
                    r["finalized"],
                    r["peers"],
                    r["kernelVersion"],
                    &r["kernelHash"].as_str().unwrap_or_default()[..10],
                    r["activeGates"],
                    r["pendingUpgrade"],
                    r["upgradeAlert"]
                )
            } else {
                format!(
                    "node {}  down  {}",
                    r["node"].as_str().unwrap_or_default(),
                    r["error"].as_str().unwrap_or_default()
                )
            }
        })
        .collect();
    Ok(lines.join("\n"))
}

/// What `orange devnet wait` waits for.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Conditions {
    /// `--head`.
    pub head: Option<u64>,
    /// `--finalized`.
    pub finalized: Option<u64>,
    /// `--peers`.
    pub peers: Option<u64>,
    /// `--kernel-version`.
    pub kernel_version: Option<u64>,
    /// `--kernel-hash`.
    pub kernel_hash: Option<Vec<u8>>,
    /// `--active-gates`, as a bit set.
    pub active_gates: Option<u64>,
    /// `--signalled`, as a bit set.
    pub signalled: Option<u64>,
    /// `--locked-in`, as a bit set.
    pub locked_in: Option<u64>,
    /// `--certified <n> --above <h>`.
    pub certified: Option<(u64, u64)>,
    /// `--caught-up`.
    pub caught_up: bool,
    /// `--no-equivocations`.
    pub no_equivocations: bool,
}

impl std::fmt::Display for Conditions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let gates = |mask: u64| {
            orange_rpc::telemetry::gates(mask)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let mut parts = Vec::new();
        if let Some(n) = self.head {
            parts.push(format!("head >= {n}"));
        }
        if let Some(n) = self.finalized {
            parts.push(format!("finalized >= {n}"));
        }
        if let Some(n) = self.peers {
            parts.push(format!("peers >= {n}"));
        }
        if let Some(v) = self.kernel_version {
            parts.push(format!("kernel version >= {v}"));
        }
        if let Some(h) = &self.kernel_hash {
            parts.push(format!("kernel hash {}", data(h)));
        }
        if let Some(g) = self.active_gates {
            parts.push(format!("gates {} active", gates(g)));
        }
        if let Some(g) = self.signalled {
            parts.push(format!("gates {} signalled by every validator", gates(g)));
        }
        if let Some(g) = self.locked_in {
            parts.push(format!("gates {} locked in", gates(g)));
        }
        if let Some((n, above)) = self.certified {
            parts.push(format!("{n} threshold certificates above {above}"));
        }
        if self.caught_up {
            parts.push("caught up".to_owned());
        }
        if self.no_equivocations {
            parts.push("no equivocations".to_owned());
        }
        f.write_str(&parts.join(", "))
    }
}

impl Conditions {
    /// Reads the conditions from the arguments.
    ///
    /// # Errors
    /// If a value does not parse or no condition is given.
    pub fn parse(args: &[String]) -> Result<Conditions, String> {
        let n = |name: &str| crate::parse_number(args, name);
        let gates = |name: &str| arg(args, name).map(|g| parse_gates(&g)).transpose();
        let c = Conditions {
            head: n("--head")?,
            finalized: n("--finalized")?,
            peers: n("--peers")?,
            kernel_version: n("--kernel-version")?,
            kernel_hash: arg(args, "--kernel-hash")
                .map(|h| {
                    orange_rpc::methods::parse_hex(&h)
                        .ok()
                        .filter(|b| b.len() == 32)
                        .ok_or("--kernel-hash must be 32 bytes of 0x hex")
                })
                .transpose()?,
            active_gates: gates("--active-gates")?,
            signalled: gates("--signalled")?,
            locked_in: gates("--locked-in")?,
            certified: match (n("--certified")?, n("--above")?) {
                (None, _) => None,
                (Some(count), above) => Some((count, above.unwrap_or(0))),
            },
            caught_up: flag(args, "--caught-up"),
            no_equivocations: flag(args, "--no-equivocations"),
        };
        if c == Conditions::default() {
            return Err("wait: give at least one condition".to_owned());
        }
        Ok(c)
    }

    /// The features of a signal or a gate list, as a bit set.
    fn mask(list: &Value) -> u64 {
        list.as_array().map_or(0, |gates| {
            gates
                .iter()
                .filter_map(Value::as_u64)
                .filter(|g| *g < 64)
                .fold(0, |m, g| m | 1 << g)
        })
    }

    /// Every condition node `rpc` does not meet; `top` is the furthest
    /// finalized height among all the nodes, for `--caught-up`.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn unmet(&self, rpc: &str, top: u64) -> Vec<String> {
        let mut unmet = Vec::new();
        let s: Status = match client::status(rpc) {
            Ok(s) => s,
            Err(e) => return vec![format!("unreachable: {e}")],
        };
        if let Some(n) = self.head
            && s.head < n
        {
            unmet.push(format!("head {} < {n}", s.head));
        }
        if let Some(n) = self.finalized
            && s.finalized < n
        {
            unmet.push(format!("finalized {} < {n}", s.finalized));
        }
        if let Some(n) = self.peers
            && s.peers < n
        {
            unmet.push(format!("peers {} < {n}", s.peers));
        }
        if let Some(v) = self.kernel_version
            && u64::from(s.kernel_version) < v
        {
            unmet.push(format!("kernel version {} < {v}", s.kernel_version));
        }
        if let Some(h) = &self.kernel_hash
            && s.kernel_hash != h.as_slice()
        {
            unmet.push(format!("kernel hash {}", data(&s.kernel_hash)));
        }
        if let Some(g) = self.active_gates
            && s.active_gates & g != g
        {
            unmet.push(format!(
                "active gates {:?}",
                orange_rpc::telemetry::gates(s.active_gates)
            ));
        }
        if self.caught_up && s.finalized + 2 < top {
            unmet.push(format!("finalized {} behind {top}", s.finalized));
        }
        if self.no_equivocations {
            match equivocations(rpc) {
                Ok(n) if n > 0.0 => unmet.push(format!("{n} equivocations recorded")),
                Ok(_) => {}
                Err(e) => unmet.push(e),
            }
        }
        if self.signalled.is_some() || self.locked_in.is_some() {
            match client::call(rpc, "orange_upgradeStatus", &json!([])) {
                Ok(u) => {
                    if let Some(g) = self.signalled {
                        let validators = u["validators"].as_array().cloned().unwrap_or_default();
                        let missing = validators
                            .iter()
                            .filter(|v| Self::mask(&v["signal"]["features"]) != g)
                            .count();
                        if missing != 0 || validators.is_empty() {
                            unmet.push(format!("{missing} validators have not signalled"));
                        }
                    }
                    if let Some(g) = self.locked_in
                        && Self::mask(&u["gates"]["lockedIn"]) & g != g
                    {
                        unmet.push(format!("locked in {}", u["gates"]["lockedIn"]));
                    }
                }
                Err(e) => unmet.push(e),
            }
        }
        if let Some((count, above)) = self.certified {
            let from = (above + 1).max(s.finalized.saturating_sub(63));
            let certified = (from..=s.finalized)
                .filter(|h| {
                    client::call(rpc, "orange_getFinalityProof", &json!([format!("{h:#x}")]))
                        .is_ok_and(|p| !p["keyId"].is_null())
                })
                .count() as u64;
            if certified < count {
                unmet.push(format!(
                    "{certified} threshold certificates above {above} (finalized {})",
                    s.finalized
                ));
            }
        }
        unmet
    }
}

/// The equivocations node `rpc` has recorded: the driver's `equivocations`
/// counter (spec 08 §9) in its metrics, `0` before the first.
fn equivocations(rpc: &str) -> Result<f64, String> {
    let text = crate::doctor::get(client::host_port(rpc), "/metrics")?;
    let samples = orange_metrics::parse(&text).map_err(|e| format!("{rpc}/metrics: {e}"))?;
    Ok(samples
        .iter()
        .filter(|s| {
            s.name == "orange_emitted_counter_total"
                && s.label("origin") == Some("driver")
                && s.label("name") == Some("equivocations")
        })
        .map(|s| s.value)
        .sum())
}

/// `orange devnet wait`.
fn wait(args: &[String]) -> Result<String, String> {
    let conditions = Conditions::parse(args)?;
    let (all, selected) = targets(args)?;
    let timeout = Duration::from_secs(number(args, "--timeout", 600)?);
    let started = Instant::now();
    let mut last = String::new();
    let mut check = || {
        // The furthest of every node, not of the selected ones: a node
        // selected alone is always caught up with itself.
        let top = all
            .iter()
            .filter_map(|(_, rpc)| client::status(rpc).ok())
            .map(|s| s.finalized)
            .max()
            .unwrap_or(0);
        let unmet: Vec<String> = selected
            .iter()
            .filter_map(|(label, rpc)| {
                let reasons = conditions.unmet(rpc, top);
                (!reasons.is_empty()).then(|| format!("node {label}: {}", reasons.join(", ")))
            })
            .collect();
        last = unmet.join("; ");
        unmet.is_empty()
    };
    let what = format!("timeout waiting for {conditions}");
    poll_until(timeout, &what, &mut check).map_err(|e| format!("{e}: {last}"))?;
    Ok(format!(
        "ok after {:.1}s: {conditions}",
        started.elapsed().as_secs_f64()
    ))
}

/// `orange devnet node --dir <dir> --index <i> [options]`: runs node `i` of the
/// manifest in this process, as `orange node` would with the manifest's
/// addresses, the key file, the peers, the bootstrap addresses and
/// `node-<i>` as its data directory,
/// plus any other `orange node` option.
fn node(
    args: &[String],
    keep_going: &mut dyn FnMut(&orange_rpc::Rpc) -> bool,
) -> Result<(), String> {
    let devnet = Devnet::load(&dir_argument(args)?)?;
    let index = crate::parse_number(args, "--index")?
        .and_then(|n| usize::try_from(n).ok())
        .ok_or("--index <i> is required")?;
    let spec = devnet.node(index)?;
    let path = |p: PathBuf| p.to_string_lossy().into_owned();
    let mut line: Vec<String> = vec!["orange".to_owned(), "node".to_owned()];
    // Everything after `orange devnet node` but the two options read here,
    // ahead of the manifest's options: the first occurrence of an option
    // counts, so what the caller gives wins.
    let mut rest = args.iter().skip(3);
    while let Some(a) = rest.next() {
        if a == "--dir" || a == "--index" {
            rest.next();
        } else {
            line.push(a.clone());
        }
    }
    line.extend(
        [
            "--kernel",
            &path(devnet.kernel()),
            "--genesis",
            &path(devnet.genesis()),
            "--key-file",
            &path(devnet.node_dir(index).join("key")),
            "--data-dir",
            &path(devnet.node_dir(index)),
            "--listen",
            &spec.listen,
            "--rpc",
            &spec.rpc,
            // `orange devnet stop` and `down` stop it through its JSON-RPC,
            // which listens on loopback.
            "--rpc-stop",
        ]
        .iter()
        .map(ToString::to_string),
    );
    for peer in &spec.peers {
        line.extend(["--peer".to_owned(), peer.clone()]);
    }
    for addr in &spec.bootstrap {
        line.extend(["--bootstrap".to_owned(), addr.clone()]);
    }
    let mut lifeline = Lifeline::from_env();
    crate::run_inner(&line, &mut |rpc| keep_going(rpc) && lifeline.holds()).map_err(|CliError(m)| m)
}

/// Runs `orange devnet <subcommand>`; every subcommand but `node` prints its
/// report and returns, `node` runs a node until `keep_going` says otherwise.
///
/// # Errors
/// A message naming the first problem.
pub fn run(
    args: &[String],
    keep_going: &mut dyn FnMut(&orange_rpc::Rpc) -> bool,
) -> Result<(), String> {
    let report = match args.get(2).map_or("", String::as_str) {
        "init" => init(args)?,
        "up" => up(args)?,
        "down" => stop_all(&Devnet::load(&dir_argument(args)?)?)?,
        "stop" => stop_node(&Devnet::load(&dir_argument(args)?)?, node_argument(args)?)?,
        "start" => start_node(&Devnet::load(&dir_argument(args)?)?, node_argument(args)?)?,
        "status" => status(args)?,
        "wait" => wait(args)?,
        "node" => return node(args, keep_going),
        _ => return Err(crate::USAGE.to_owned()),
    };
    println!("{report}");
    Ok(())
}
