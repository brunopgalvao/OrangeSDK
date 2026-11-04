//! The soak's nodes as processes: a devnet initialized by `solo devnet
//! init`, its genesis trimmed to the genesis validators and funding the
//! load accounts, every node dialling its peers through the proxies of
//! `proxy.rs`, and the operations faults are made of: kill -9, a graceful
//! stop, a restart with or without the data directory, SIGSTOP and SIGCONT.

use std::fs::{self, File};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use solo_cli::devnet::LIFELINE;

use crate::proxy::{self, Net};
use crate::rpc;
use crate::world::{Member, Role, Shared};

/// The kernel every soak runs.
pub const KERNEL: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../solo-node/tests/fixtures/kernel.elf"
);

/// What the cluster is made of.
#[derive(Debug, Clone)]
pub struct Shape {
    pub validators: usize,
    pub standbys: usize,
    pub observers: usize,
    pub slot_ms: u64,
    pub epoch_blocks: u64,
    pub dkg_phase_blocks: u64,
}

/// One node's process side.
pub struct Proc {
    pub listen: SocketAddr,
    pub dir: PathBuf,
    pub child: Option<Child>,
    /// Addresses of the proxies it dials.
    pub peers: Vec<SocketAddr>,
    /// Set when the soak stopped it on purpose.
    pub expected_exit: bool,
    /// Where its current process's output starts in its log.
    pub log_from: usize,
}

pub struct Cluster {
    pub solo: String,
    pub root: PathBuf,
    pub devnet: PathBuf,
    pub chain_id: u64,
    pub shape: Shape,
    pub net: Arc<Net>,
    pub procs: Vec<Proc>,
    /// The standbys' consensus keys, by member id.
    pub keys: Vec<Option<SigningKey>>,
    /// Every address genesis funds.
    pub funded: Vec<String>,
    pub world: Shared,
    /// Kills every node of the run once this test process is gone.
    watchdog: Option<Child>,
}

fn free_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
}

fn path(p: &Path) -> &str {
    p.to_str().expect("UTF-8 path")
}

impl Cluster {
    /// Initializes the devnet in `root`, funding `load` with `funding` wei
    /// each.
    #[allow(clippy::too_many_lines)]
    pub fn init(
        solo: &str,
        root: &Path,
        shape: &Shape,
        seed: u64,
        load: &[[u8; 20]],
        funding: u128,
        world: Shared,
    ) -> Cluster {
        let devnet = root.join("devnet");
        let keyed = shape.validators + shape.standbys;
        let seed_hex = format!("0x{:064x}", u128::from(seed) << 1 | 1);
        let out = Command::new(solo)
            .args(["devnet", "init", "--dir", path(&devnet), "--kernel", KERNEL])
            .args(["--validators", &keyed.to_string()])
            .args(["--p2p-port", "0", "--rpc-port", "0"])
            .args(["--slot-ms", &shape.slot_ms.to_string()])
            .args(["--epoch-blocks", &shape.epoch_blocks.to_string()])
            .args(["--dkg-phase-blocks", &shape.dkg_phase_blocks.to_string()])
            .args(["--seed", &seed_hex])
            .output()
            .expect("solo devnet init");
        assert!(
            out.status.success(),
            "devnet init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The genesis: the standbys are funded but not members, and the
        // load accounts are funded.
        let genesis_path = devnet.join("genesis.json");
        let mut genesis: Value =
            serde_json::from_str(&fs::read_to_string(&genesis_path).unwrap()).unwrap();
        let ids: Vec<Value> = genesis["validators"].as_array().unwrap().clone();
        genesis["validators"] = Value::Array(ids[..shape.validators].to_vec());
        if let Some(keys) = genesis["staking"]["keys"].as_object_mut() {
            for id in &ids[shape.validators..] {
                keys.remove(id.as_str().unwrap());
            }
        }
        for a in load {
            genesis["alloc"][rpc::hex(a)] = json!(funding.to_string());
        }
        let funded: Vec<String> = genesis["alloc"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.to_lowercase())
            .collect();
        fs::write(
            &genesis_path,
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();
        // The manifest: no bootstrap addresses, the proxies are given as
        // peers on the command line.
        let manifest_path = devnet.join("devnet.json");
        let mut manifest: Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let chain_id = manifest["chainId"].as_u64().unwrap();
        let mut members = Vec::new();
        let mut procs = Vec::new();
        let mut keys = Vec::new();
        let started = Instant::now();
        for (i, node) in manifest["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            node["bootstrap"] = json!([]);
            node["peers"] = json!([]);
            let role = if i < shape.validators {
                Role::Validator
            } else {
                Role::Standby
            };
            let label = match role {
                Role::Validator => format!("v{i}"),
                _ => format!("s{}", i - shape.validators),
            };
            let key_hex = fs::read_to_string(devnet.join(format!("node-{i}/key"))).unwrap();
            keys.push(Some(solo_cli::parse_key(key_hex.trim()).unwrap()));
            members.push(member(
                i,
                role,
                label,
                node["rpc"].as_str().unwrap(),
                started,
            ));
            procs.push(Proc {
                listen: node["listen"].as_str().unwrap().parse().unwrap(),
                dir: devnet.join(format!("node-{i}")),
                child: None,
                peers: Vec::new(),
                expected_exit: false,
                log_from: 0,
            });
        }
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        world.lock().unwrap().members = members;
        let mut cluster = Cluster {
            solo: solo.to_owned(),
            root: root.to_path_buf(),
            devnet,
            chain_id,
            shape: shape.clone(),
            net: Arc::new(Net::default()),
            procs,
            keys,
            funded,
            world,
            watchdog: None,
        };
        // Every keyed node dials every other through its own proxy.
        for a in 0..keyed {
            for b in 0..keyed {
                if a != b {
                    let p = proxy::spawn(&cluster.net, a, b, cluster.procs[b].listen);
                    cluster.procs[a].peers.push(p);
                }
            }
        }
        for _ in 0..shape.observers {
            cluster.add_observer();
        }
        cluster.watchdog = Some(watchdog(&cluster.root));
        cluster
    }

    /// Adds an observer (not started); its member id.
    pub fn add_observer(&mut self) -> usize {
        let id = self.procs.len();
        let n = id - self.shape.validators - self.shape.standbys;
        let listen = free_addr();
        let rpc = free_addr();
        let dir = self.root.join(format!("observer-{n}"));
        let keyed = self.shape.validators + self.shape.standbys;
        let peers = (0..keyed)
            .map(|b| proxy::spawn(&self.net, id, b, self.procs[b].listen))
            .collect();
        self.procs.push(Proc {
            listen,
            dir,
            child: None,
            peers,
            expected_exit: false,
            log_from: 0,
        });
        self.keys.push(None);
        self.world.lock().unwrap().members.push(member(
            id,
            Role::Observer,
            format!("o{n}"),
            &rpc.to_string(),
            Instant::now(),
        ));
        id
    }

    pub fn label(&self, id: usize) -> String {
        self.world.lock().unwrap().members[id].label.clone()
    }

    pub fn role(&self, id: usize) -> Role {
        self.world.lock().unwrap().members[id].role
    }

    /// Starts node `id`; `wipe` empties its data directory first (its key
    /// and log kept), `sync` has it fetch its state from its peers.
    pub fn start(&mut self, id: usize, wipe: bool, sync: bool) {
        let role = self.role(id);
        let p = &mut self.procs[id];
        assert!(p.child.is_none(), "node {id} already runs");
        if wipe {
            wipe_dir(&p.dir);
        }
        fs::create_dir_all(&p.dir).unwrap();
        let fresh = !p.dir.join("chain.redb").exists()
            && fs::read_dir(&p.dir).map_or(true, |d| {
                d.filter_map(Result::ok)
                    .all(|e| ["key", "log", "pid"].contains(&e.file_name().to_str().unwrap_or("")))
            });
        let log_path = p.dir.join("log");
        p.log_from = fs::metadata(&log_path).map_or(0, |m| usize::try_from(m.len()).unwrap_or(0));
        let log = File::options()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        let rpc = self.world.lock().unwrap().members[id].rpc.clone();
        let mut command = Command::new(&self.solo);
        command.env(LIFELINE, std::process::id().to_string());
        if role == Role::Observer {
            command
                .arg("node")
                .args(["--kernel", path(&self.devnet.join("kernel.solo"))])
                .args(["--genesis", path(&self.devnet.join("genesis.json"))])
                .args(["--data-dir", path(&p.dir)])
                .args(["--listen", &p.listen.to_string()])
                .args(["--rpc", &rpc]);
        } else {
            command
                .args(["devnet", "node", "--dir", path(&self.devnet)])
                .args(["--index", &id.to_string()])
                .arg("--serve-snapshots");
        }
        command.arg("--no-discovery");
        if sync {
            command.arg("--sync-from-peers");
            // A chain with staking trusts a key set, not its genesis set
            // (spec 22 §7.2), and follows the chain's handoffs from it to
            // the snapshot it fetches (§7.5).
            if let Some(key) = self.world.lock().unwrap().trust_key() {
                command.args(["--trust-key", &key]);
            }
        }
        for peer in &p.peers {
            command.args(["--peer", &peer.to_string()]);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start a node");
        let pid = child.id();
        p.child = Some(child);
        p.expected_exit = false;
        let mut w = self.world.lock().unwrap();
        let m = &mut w.members[id];
        m.pid = Some(pid);
        m.generation += 1;
        m.frozen = false;
        m.started = Instant::now();
        m.resumed = m.started;
        m.fresh = fresh;
        m.syncs = sync;
        let (label, generation) = (m.label.clone(), m.generation);
        w.last_restart = Some(Instant::now());
        let how = match (fresh, sync) {
            (true, true) => " from nothing, syncing from peers",
            (true, false) => " from nothing",
            (false, _) => "",
        };
        w.log(format!("start {label} (#{generation}, pid {pid}){how}"));
    }

    /// kill -9.
    pub fn kill(&mut self, id: usize) {
        let label = self.label(id);
        let p = &mut self.procs[id];
        if let Some(mut child) = p.child.take() {
            p.expected_exit = true;
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut w = self.world.lock().unwrap();
        w.members[id].pid = None;
        w.members[id].frozen = false;
        w.log(format!("kill -9 {label}"));
    }

    /// A graceful stop through `solo_stop`; false when it did not stop in
    /// time (it is killed then).
    pub fn stop(&mut self, id: usize) -> bool {
        let (label, rpc_addr, frozen) = {
            let w = self.world.lock().unwrap();
            let m = &w.members[id];
            (m.label.clone(), m.rpc.clone(), m.frozen)
        };
        if frozen {
            self.thaw(id);
        }
        let p = &mut self.procs[id];
        let Some(mut child) = p.child.take() else {
            return true;
        };
        p.expected_exit = true;
        // Going down from now on: the checker no longer expects answers.
        self.world.lock().unwrap().members[id].pid = None;
        if let Err(rpc::Fail::Transport(_)) =
            rpc::call(&rpc_addr, "solo_stop", &json!([]), Duration::from_secs(10))
        {
            // No RPC yet (a state sync runs before it is up): nothing to
            // ask, so it is killed.
            let _ = child.kill();
            let _ = child.wait();
            let mut w = self.world.lock().unwrap();
            w.members[id].pid = None;
            w.log(format!(
                "killed {label}: it served no RPC to stop it through"
            ));
            return true;
        }
        let deadline = Instant::now() + Duration::from_mins(1);
        let mut stopped = None;
        while Instant::now() < deadline {
            if let Ok(Some(status)) = child.try_wait() {
                stopped = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut w = self.world.lock().unwrap();
        w.members[id].pid = None;
        match stopped {
            Some(status) if status.success() => {
                w.log(format!("stopped {label}"));
                true
            }
            Some(status) => {
                w.violate(format!("{label} exited with {status} on a graceful stop"));
                true
            }
            None => {
                w.violate(format!("{label} did not stop within a minute of solo_stop"));
                drop(w);
                let _ = child.kill();
                let _ = child.wait();
                false
            }
        }
    }

    fn signal(&self, id: usize, signal: &str) {
        if let Some(child) = &self.procs[id].child {
            let _ = Command::new("kill")
                .args([signal, &child.id().to_string()])
                .status();
        }
    }

    /// SIGSTOP.
    pub fn freeze(&mut self, id: usize) {
        if self.procs[id].child.is_none() {
            return;
        }
        self.signal(id, "-STOP");
        let mut w = self.world.lock().unwrap();
        w.members[id].frozen = true;
        let label = w.members[id].label.clone();
        w.log(format!("freeze {label} (SIGSTOP)"));
    }

    /// SIGCONT.
    pub fn thaw(&mut self, id: usize) {
        self.signal(id, "-CONT");
        let mut w = self.world.lock().unwrap();
        if w.members[id].frozen {
            w.members[id].frozen = false;
            w.members[id].resumed = Instant::now();
            let label = w.members[id].label.clone();
            w.log(format!("thaw {label} (SIGCONT)"));
        }
    }

    /// Takes node `id` out of the run for good: killed, its directory gone.
    pub fn retire(&mut self, id: usize) {
        self.kill(id);
        // Its state goes; its log stays for a report.
        wipe_dir(&self.procs[id].dir);
        let mut w = self.world.lock().unwrap();
        w.members[id].retired = true;
        let label = w.members[id].label.clone();
        w.log(format!("retire {label}"));
    }

    /// Nodes whose process ended without the soak asking: each a violation.
    pub fn reap(&mut self) {
        for id in 0..self.procs.len() {
            let p = &mut self.procs[id];
            let Some(child) = p.child.as_mut() else {
                continue;
            };
            if let Ok(Some(status)) = child.try_wait() {
                p.child = None;
                // A state sync that fails is a violation like any other
                // exit: a joiner follows the chain's handoffs from the key
                // set it trusts (spec 22 §7.5), so no retry under a newer
                // key is needed.
                let tail = tail(&p.dir.join("log"), 30);
                let mut w = self.world.lock().unwrap();
                w.members[id].pid = None;
                let label = w.members[id].label.clone();
                w.violate(format!(
                    "{label} exited on its own with {status}; its log ends:\n{tail}"
                ));
            }
        }
    }

    pub fn running(&self, id: usize) -> bool {
        self.procs[id].child.is_some()
    }

    /// Every node, stopped gracefully; the watchdog too.
    pub fn shutdown(&mut self) {
        for id in 0..self.procs.len() {
            if self.procs[id].child.is_some() {
                self.stop(id);
            }
        }
        self.net.stop();
        if let Some(mut w) = self.watchdog.take() {
            let _ = w.kill();
            let _ = w.wait();
        }
    }

    /// Every log, as (label, path).
    pub fn logs(&self) -> Vec<(String, PathBuf)> {
        (0..self.procs.len())
            .map(|id| (self.label(id), self.procs[id].dir.join("log")))
            .collect()
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for p in &mut self.procs {
            if let Some(mut child) = p.child.take() {
                let _ = Command::new("kill")
                    .args(["-CONT", &child.id().to_string()])
                    .status();
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        self.net.stop();
        if let Some(mut w) = self.watchdog.take() {
            let _ = w.kill();
            let _ = w.wait();
        }
    }
}

fn member(id: usize, role: Role, label: String, rpc: &str, started: Instant) -> Member {
    Member {
        id,
        role,
        label,
        rpc: rpc.to_owned(),
        pid: None,
        generation: 0,
        frozen: false,
        impaired: false,
        started,
        resumed: started,
        fresh: true,
        syncs: false,
        retired: false,
    }
}

/// Empties a data directory but for the key and the log.
fn wipe_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.filter_map(Result::ok) {
            let name = e.file_name();
            if name == "key" || name == "log" {
                continue;
            }
            let p = e.path();
            if fs::remove_dir_all(&p).is_err() {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

/// The last `n` lines of a file.
pub fn tail(path: &Path, n: usize) -> String {
    let text = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// A shell that waits for this process to go and then kills every process
/// whose command line names `root`: the observers, which have no lifeline
/// of their own, and anything else a killed run would leave.
fn watchdog(root: &Path) -> Child {
    let script = format!(
        "while kill -0 {pid} 2>/dev/null; do sleep 1; done; pkill -CONT -f '{root}'; pkill -9 -f '{root}/'",
        pid = std::process::id(),
        root = root.display()
    );
    Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("watchdog")
}
