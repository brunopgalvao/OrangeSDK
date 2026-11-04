//! The soak: a devnet of real `solo` processes run for minutes to hours
//! under load and a seeded schedule of faults, its invariants checked all
//! the while. It finds the timing and lifecycle bugs short tests miss.
//!
//! A run starts 4 to 7 genesis validators, standbys (keyed nodes outside
//! the genesis set that join it by staking, and leave it again) and
//! observers, all on `solo devnet` with epochs short enough that a DKG run
//! and a key rotation happen every few seconds. Every connection between
//! two nodes runs through a proxy of the soak's (`proxy.rs`), so links can
//! be cut and slowed. A load generator (`load.rs`) sends value transfers
//! and calls to a counter contract to random live nodes. The scheduler
//! (`faults.rs`) draws from the seed: kill -9 and restart, with the data
//! directory kept or wiped (a wiped node catches up from its peers' blocks
//! or syncs state from their snapshots, `--sync-from-peers`; a wiped
//! validator does either under its signing guard, spec 08 §7b, which keeps
//! it from signing again in the views it signed in before its wipe);
//! graceful restarts through `solo_stop`; one node isolated; partitions,
//! with and without a quorum; slow links; SIGSTOP; more validators down
//! than the network tolerates; flapping links; fresh observers joining
//! with `--sync-from-peers` while older ones retire; standbys registering,
//! bonding and unbonding. The checker (`check.rs`) holds the invariants it
//! documents; the load holds that every accepted transaction reaches a
//! block (`load.rs`). The run ends with everything healed: every node
//! catches up, a new threshold key set certifies blocks, every open
//! transaction lands, and every node stops cleanly.
//!
//! A failure writes the seed, the configuration, the fault timeline, the
//! violations and every node's log to a report directory (named on the
//! panic) and fails the test.
//!
//! Both tests are `#[ignore]`d: they run real processes for minutes.
//!
//! ```text
//! # the short, deterministic schedule (fixed seed, about four minutes):
//! cargo test -p solo-cli --test soak -- --ignored soak_short --nocapture
//! # the long one, for local use:
//! SOLO_SOAK_SECS=3600 SOLO_SOAK_SEED=7 cargo test --release -p solo-cli --test soak -- --ignored soak_long --nocapture
//! ```
//!
//! Knobs (environment): `SOLO_SOAK_SEED` (the schedule; the long run
//! draws one from the clock and prints it), `SOLO_SOAK_SECS` (how long
//! faults are injected; default 180 short, 3600 long), `SOLO_SOAK_VALIDATORS`
//! (4 to 7; the long run's default comes from the seed),
//! `SOLO_SOAK_STANDBYS`, `SOLO_SOAK_OBSERVERS`, `SOLO_SOAK_EPOCH` (blocks),
//! `SOLO_SOAK_REPORT` (where a failure's report goes; default the system
//! temp dir), `SOLO_SOAK_KEEP` (keep the nodes' directories),
//! `SOLO_SOAK_KEEP_FAILED` (keep them when the run fails) and `SOLO_BIN` (the `solo` binary; default the one Cargo
//! built for this test).

mod check;
mod cluster;
mod faults;
mod load;
mod proxy;
mod rpc;
mod world;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use solo_scratch::Scratch;

use crate::check::Checker;
use crate::cluster::{Cluster, Shape};
use crate::faults::Scheduler;
use crate::load::Load;
use crate::world::{Shared, World};

const SOLO: &str = env!("CARGO_BIN_EXE_solo");

/// The short run's seed.
const SHORT_SEED: u64 = 20_261_104;

/// Load accounts and the addresses they pay.
const SENDERS: usize = 8;
const RECIPIENTS: usize = 16;
const ETHER: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone)]
struct Config {
    name: &'static str,
    seed: u64,
    duration: Duration,
    shape: Shape,
    /// Scales the spells of the schedule.
    scale: f64,
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

impl Config {
    fn short() -> Config {
        let seed = env_u64("SOLO_SOAK_SEED").unwrap_or(SHORT_SEED);
        Config {
            name: "short",
            seed,
            duration: Duration::from_secs(env_u64("SOLO_SOAK_SECS").unwrap_or(180)),
            shape: Shape {
                validators: env_usize("SOLO_SOAK_VALIDATORS").unwrap_or(4),
                standbys: env_usize("SOLO_SOAK_STANDBYS").unwrap_or(1),
                observers: env_usize("SOLO_SOAK_OBSERVERS").unwrap_or(1),
                slot_ms: 400,
                epoch_blocks: env_u64("SOLO_SOAK_EPOCH").unwrap_or(16),
                dkg_phase_blocks: 3,
            },
            scale: 0.6,
        }
    }

    fn long() -> Config {
        let seed = env_u64("SOLO_SOAK_SEED").unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(1, |d| d.as_secs())
        });
        let validators =
            env_usize("SOLO_SOAK_VALIDATORS").unwrap_or(4 + usize::try_from(seed % 4).unwrap());
        Config {
            name: "long",
            seed,
            duration: Duration::from_secs(env_u64("SOLO_SOAK_SECS").unwrap_or(3600)),
            shape: Shape {
                validators,
                standbys: env_usize("SOLO_SOAK_STANDBYS").unwrap_or(2),
                observers: env_usize("SOLO_SOAK_OBSERVERS").unwrap_or(2),
                slot_ms: 400,
                epoch_blocks: env_u64("SOLO_SOAK_EPOCH").unwrap_or(20),
                dkg_phase_blocks: 4,
            },
            scale: 1.0,
        }
    }
}

#[test]
#[ignore = "runs real node processes for about four minutes"]
fn soak_short() {
    soak(&Config::short());
}

#[test]
#[ignore = "runs real node processes for an hour by default"]
fn soak_long() {
    soak(&Config::long());
}

struct Run {
    world: Shared,
    checker: Arc<Mutex<Checker>>,
    load: Arc<Mutex<Load>>,
    generate: Arc<Mutex<bool>>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

#[allow(clippy::too_many_lines)]
fn soak(config: &Config) {
    let solo = std::env::var("SOLO_BIN").unwrap_or_else(|_| SOLO.to_owned());
    let scratch = Scratch::dir("soak", &format!("{}-{}", config.name, config.seed));
    let root = scratch.path().to_path_buf();
    eprintln!(
        "soak {}: seed {} for {}s, {:?}, in {}",
        config.name,
        config.seed,
        config.duration.as_secs(),
        config.shape,
        root.display()
    );
    let world: Shared = Arc::new(Mutex::new(World::new()));
    let keys = load::keys(config.seed, SENDERS);
    let addresses: Vec<[u8; 20]> = keys.iter().map(load::address).collect();
    let to = load::recipients(config.seed, RECIPIENTS);
    let cluster = Cluster::init(
        &solo,
        &root,
        &config.shape,
        config.seed,
        &addresses,
        1_000 * ETHER,
        Arc::clone(&world),
    );
    let chain_id = cluster.chain_id;
    let mut accounts: Vec<String> = cluster.funded.clone();
    accounts.extend(to.iter().map(|a| rpc::hex(a)));
    accounts.push(rpc::hex(&solo_abi::staking::STAKING_ADDRESS));
    accounts.push(rpc::hex(&solo_abi::fees::FEE_VAULT));
    let deployer = rpc::hex(&addresses[0]);
    let logs = cluster.logs();
    let mut sched = Scheduler::new(
        cluster,
        Arc::clone(&world),
        config.seed,
        config.scale,
        config.shape.observers + 1,
    );
    let started = Instant::now();
    for id in 0..sched.cluster.procs.len() {
        sched.cluster.start(id, false, false);
    }
    let up = sched.wait_for(Duration::from_mins(3), |s| s.caught_up(2, 3));
    if !up {
        world
            .lock()
            .unwrap()
            .violate("the network did not start finalizing within three minutes");
    }
    let run = Run {
        checker: Arc::new(Mutex::new(Checker::new(
            Arc::clone(&world),
            accounts,
            deployer,
            config.seed,
        ))),
        load: Arc::new(Mutex::new(Load::new(
            Arc::clone(&world),
            chain_id,
            keys,
            to,
            config.seed,
        ))),
        generate: Arc::new(Mutex::new(true)),
        world: Arc::clone(&world),
        threads: Vec::new(),
    };
    let mut run = run;
    {
        let (world, checker) = (Arc::clone(&run.world), Arc::clone(&run.checker));
        run.threads.push(std::thread::spawn(move || {
            while !world.lock().unwrap().done {
                checker.lock().unwrap().cycle();
                std::thread::sleep(Duration::from_secs(1));
            }
        }));
        let (world, load, generate) = (
            Arc::clone(&run.world),
            Arc::clone(&run.load),
            Arc::clone(&run.generate),
        );
        run.threads.push(std::thread::spawn(move || {
            while !world.lock().unwrap().done {
                let g = *generate.lock().unwrap();
                load.lock().unwrap().turn(g);
                std::thread::sleep(Duration::from_millis(200));
            }
        }));
    }
    // The schedule.
    let deadline = Instant::now() + config.duration;
    let mut ok = up;
    while ok && Instant::now() < deadline {
        ok = sched.calm();
        // A fault starts on a network that has caught up from the last.
        if ok && !sched.wait_for(check::CATCHUP_BOUND, |s| s.caught_up(4, 0)) {
            world
                .lock()
                .unwrap()
                .violate("the nodes did not catch up with each other in a calm spell");
            ok = false;
        }
        if ok && Instant::now() < deadline {
            ok = sched.fault();
        }
    }
    // The end: everything healed, every node caught up, a fresh key, every
    // transaction in a block.
    if ok {
        world
            .lock()
            .unwrap()
            .log("end of the schedule: healing everything");
        sched.heal_all();
        final_checks(&mut sched, &run);
    }
    // The checker and the load stop first: nodes going down are no fault.
    world.lock().unwrap().done = true;
    for t in run.threads.drain(..) {
        let _ = t.join();
    }
    world.lock().unwrap().log("stopping every node");
    sched.cluster.shutdown();
    for (label, path) in &logs {
        let log = fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = log.lines().find(|l| l.contains("panicked")) {
            world
                .lock()
                .unwrap()
                .violate(format!("{label} panicked: {line}"));
        }
    }
    let report = summary(config, &run, &sched, started.elapsed());
    eprintln!("{report}");
    let violations = world.lock().unwrap().violations.clone();
    if std::env::var_os("SOLO_SOAK_KEEP").is_some()
        || (!violations.is_empty() && std::env::var_os("SOLO_SOAK_KEEP_FAILED").is_some())
    {
        eprintln!("soak: SOLO_SOAK_KEEP is set; {} stays", root.display());
        std::mem::forget(scratch);
    }
    if violations.is_empty() {
        return;
    }
    let dir = write_report(config, &world, &report, &sched.cluster.logs());
    panic!(
        "soak {} seed {} failed with {} violation(s); report in {}:\n{}",
        config.name,
        config.seed,
        violations.len(),
        dir.display(),
        violations.join("\n")
    );
}

fn final_checks(sched: &mut Scheduler, run: &Run) {
    let world = &run.world;
    if !sched.wait_for(Duration::from_mins(5), |s| s.caught_up(2, 0)) {
        world
            .lock()
            .unwrap()
            .violate("after the final heal the nodes did not catch up within five minutes");
        return;
    }
    world.lock().unwrap().log("every node caught up");
    // A key set newer than every one seen so far certifies blocks.
    let newest = world.lock().unwrap().chain.key_ids.keys().max().copied();
    let epoch_secs = sched.cluster.shape.epoch_blocks;
    let rotated = sched.wait_for(Duration::from_secs(60 + 8 * epoch_secs), |_| {
        world
            .lock()
            .unwrap()
            .chain
            .key_ids
            .keys()
            .max()
            .is_some_and(|k| Some(*k) > newest)
    });
    if !rotated {
        world.lock().unwrap().violate(format!(
            "no threshold key set after {newest:?} certified a block after the final heal"
        ));
        return;
    }
    // Every transaction the load sent lands.
    *run.generate.lock().unwrap() = false;
    let load = Arc::clone(&run.load);
    let landed = sched.wait_for(Duration::from_mins(4), |s| {
        load.lock().unwrap().open() == 0 && !s.staking_open()
    });
    if !landed {
        let open = run.load.lock().unwrap().describe_open();
        world.lock().unwrap().violate(format!(
            "transactions still open four minutes after the final heal:\n{open}"
        ));
        return;
    }
    // One more conservation check over the last blocks.
    std::thread::sleep(Duration::from_secs(25));
    run.checker.lock().unwrap().cycle();
}

fn summary(config: &Config, run: &Run, sched: &Scheduler, elapsed: Duration) -> String {
    let stats = run.load.lock().unwrap().stats.clone();
    let checker = run.checker.lock().unwrap();
    let nodes = checker.summaries();
    let w = run.world.lock().unwrap();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "soak {} seed {}: {:.0}s, {} faults, finalized {}, {} key sets ({:?}), validator set of {}",
        config.name,
        config.seed,
        elapsed.as_secs_f64(),
        sched.faults,
        w.chain.scanned,
        w.chain.key_ids.len(),
        w.chain.key_ids,
        w.chain.set.len()
    );
    let _ = writeln!(
        s,
        "  load: {} accepted, {} included ({} failed), {} lost with restarts and resent, {} refusals; {} conservation checks, {} counter calls",
        stats.sent,
        stats.included,
        stats.failed,
        stats.lost,
        stats.refused,
        checker.balance_checks,
        w.chain.counter_calls
    );
    for n in nodes {
        let _ = writeln!(
            s,
            "  {:4} starts {:2}  finalized {:6}  rss {:?}..{} KiB  files {:?}..{}  slowest status {} ms",
            n.label,
            n.generations,
            n.finalized,
            n.rss_base_kb,
            n.rss_max_kb,
            n.fd_base,
            n.fd_max,
            n.latency_max_ms
        );
    }
    for warning in &w.warnings {
        let _ = writeln!(s, "  warning {warning}");
    }
    for v in &w.violations {
        let _ = writeln!(s, "  VIOLATION {v}");
    }
    s
}

fn write_report(
    config: &Config,
    world: &Shared,
    summary: &str,
    logs: &[(String, PathBuf)],
) -> PathBuf {
    let base =
        std::env::var("SOLO_SOAK_REPORT").map_or_else(|_| std::env::temp_dir(), PathBuf::from);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let dir = base.join(format!("solo-soak-{}-{}-{stamp}", config.name, config.seed));
    let _ = fs::create_dir_all(&dir);
    let w = world.lock().unwrap();
    let mut text = format!(
        "seed {}\nconfig {config:?}\nreplay: SOLO_SOAK_SEED={} with the same SOLO_SOAK_* knobs\n\n{summary}\n\ntimeline:\n",
        config.seed, config.seed
    );
    for line in &w.timeline {
        text.push_str(line);
        text.push('\n');
    }
    let _ = fs::write(dir.join("report.txt"), text);
    for (label, path) in logs {
        let _ = copy(path, &dir.join(format!("{label}.log")));
    }
    dir
}

fn copy(from: &Path, to: &Path) -> std::io::Result<u64> {
    fs::copy(from, to)
}
