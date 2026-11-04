//! The health verdict `solo doctor` prints (spec 11 §7): the same
//! conditions as the alert rules in `ops/alerts.yml`, judged from one
//! `/status` document and one `/metrics` scrape instead of a time series.

use crate::node::{KERNEL_CALL_SECONDS, KERNEL_FAULTS, Status};
use crate::parse::Sample;

/// Entrypoints that run once per kernel, at open or around a switchover,
/// and so say nothing about how the node keeps up: the call-time check skips them.
pub const ONE_OFF_ENTRYPOINTS: [&str; 3] = ["kernel_init", "kernel_migrate", "kernel_version"];

/// Thresholds of the verdict. [`Limits::default`] matches the alert rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// Most seconds the head may go without advancing.
    pub max_head_age_seconds: f64,
    /// Most blocks the finalized height may trail the head by.
    pub max_finality_lag: u64,
    /// Fewest peers a node with a transport may have.
    pub min_peers: u64,
    /// Most transactions the mempool may hold.
    pub max_mempool: u64,
    /// Most seconds a kernel entrypoint may take per call, on average.
    pub max_call_seconds: f64,
}

/// The defaults, shared with `ops/alerts.yml`.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_head_age_seconds: 60.0,
    max_finality_lag: 16,
    min_peers: 1,
    max_mempool: 1000,
    max_call_seconds: 1.0,
};

impl Default for Limits {
    fn default() -> Limits {
        DEFAULT_LIMITS
    }
}

/// Every reason the node is unhealthy; empty means healthy.
#[must_use]
pub fn assess(status: &Status, samples: &[Sample], limits: &Limits) -> Vec<String> {
    let mut problems = Vec::new();
    if status.head_age_seconds > limits.max_head_age_seconds {
        problems.push(format!(
            "head {} has not advanced for {:.0}s (limit {}s)",
            status.head, status.head_age_seconds, limits.max_head_age_seconds
        ));
    }
    let lag = status.head.saturating_sub(status.finalized);
    if lag > limits.max_finality_lag {
        problems.push(format!(
            "finalized height {} trails the head by {lag} blocks (limit {})",
            status.finalized, limits.max_finality_lag
        ));
    }
    if status.p2p && status.peers < limits.min_peers {
        problems.push(format!(
            "{} peers connected (minimum {})",
            status.peers, limits.min_peers
        ));
    }
    if status.mempool > limits.max_mempool {
        problems.push(format!(
            "{} transactions waiting in the mempool (limit {})",
            status.mempool, limits.max_mempool
        ));
    }
    for s in samples.iter().filter(|s| s.name == KERNEL_FAULTS.name) {
        if s.value > 0.0 {
            problems.push(format!(
                "{} faulted {} times ({}) since the node started",
                s.label("entrypoint").unwrap_or("?"),
                s.value,
                s.label("status").unwrap_or("?"),
            ));
        }
    }
    let sum_name = format!("{}_sum", KERNEL_CALL_SECONDS.name);
    let count_name = format!("{}_count", KERNEL_CALL_SECONDS.name);
    let repeated = |s: &&Sample| {
        s.name == sum_name
            && !s
                .label("entrypoint")
                .is_some_and(|e| ONE_OFF_ENTRYPOINTS.contains(&e))
    };
    for sum in samples.iter().filter(repeated) {
        let entrypoint = sum.label("entrypoint");
        let count = samples
            .iter()
            .find(|c| c.name == count_name && c.label("entrypoint") == entrypoint)
            .map_or(0.0, |c| c.value);
        let mean = sum.value / count;
        if count > 0.0 && mean > limits.max_call_seconds {
            problems.push(format!(
                "{} takes {mean:.3}s per call on average (limit {}s)",
                entrypoint.unwrap_or("?"),
                limits.max_call_seconds
            ));
        }
    }
    if let Some(why) = &status.upgrade_alert {
        problems.push(format!(
            "the pending kernel upgrade cannot be enacted: {why}"
        ));
    }
    if status.missing_gates != 0 {
        let gates: Vec<String> = (0..64)
            .filter(|g| status.missing_gates >> g & 1 == 1)
            .map(|g: u32| g.to_string())
            .collect();
        problems.push(format!(
            "the chain locked in feature gates this release does not support: {}",
            gates.join(", ")
        ));
    }
    problems
}

/// One line describing the node, for the top of the report.
#[must_use]
pub fn summary(status: &Status) -> String {
    let peers = if status.p2p {
        format!("{} peers", status.peers)
    } else {
        "no p2p".to_owned()
    };
    let name = if status.chain_name.is_empty() {
        String::new()
    } else {
        format!(" ({})", status.chain_name)
    };
    format!(
        "solo {}: chain {}{name}, head {} ({:.1}s ago), finalized {}, {peers}, mempool {}, up {:.0}s",
        status.version,
        status.chain_id,
        status.head,
        status.head_age_seconds,
        status.finalized,
        status.mempool,
        status.uptime_seconds
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse;

    fn status() -> Status {
        Status {
            version: "0.0.1".to_owned(),
            chain_id: 1337,
            chain_name: String::new(),
            head: 40,
            head_age_seconds: 0.25,
            finalized: 40,
            p2p: true,
            peers: 3,
            mempool: 2,
            uptime_seconds: 12.0,
            validator: None,
            upgrade_alert: None,
            missing_gates: 0,
            kernel_version: 1,
            kernel_hash: [0; 32],
            active_gates: 0,
            pending_upgrade: None,
        }
    }

    #[test]
    fn healthy_node() {
        let metrics = parse(
            "solo_kernel_faults_total{entrypoint=\"kernel_query\",status=\"trap\"} 0\n\
             solo_kernel_call_duration_seconds_sum{entrypoint=\"kernel_driver_step\"} 0.5\n\
             solo_kernel_call_duration_seconds_count{entrypoint=\"kernel_driver_step\"} 100\n\
             solo_kernel_call_duration_seconds_sum{entrypoint=\"kernel_query\"} 0\n\
             solo_kernel_call_duration_seconds_sum{entrypoint=\"kernel_init\"} 9\n\
             solo_kernel_call_duration_seconds_count{entrypoint=\"kernel_init\"} 1\n",
        )
        .unwrap();
        assert!(assess(&status(), &metrics, &Limits::default()).is_empty());
        assert_eq!(
            summary(&status()),
            "solo 0.0.1: chain 1337, head 40 (0.2s ago), finalized 40, 3 peers, mempool 2, up 12s"
        );
        let named = Status {
            chain_name: "tangerine".to_owned(),
            ..status()
        };
        assert!(summary(&named).starts_with("solo 0.0.1: chain 1337 (tangerine), head 40"));
        let dev = Status {
            p2p: false,
            peers: 0,
            ..status()
        };
        assert!(assess(&dev, &[], &DEFAULT_LIMITS).is_empty());
        assert!(summary(&dev).contains("no p2p"));
    }

    #[test]
    fn every_problem_is_reported() {
        let sick = Status {
            head_age_seconds: 75.0,
            finalized: 20,
            peers: 0,
            mempool: 1001,
            upgrade_alert: Some("this host cannot load upgrade 0x01".to_owned()),
            missing_gates: 0b101,
            ..status()
        };
        let metrics = parse(
            "solo_kernel_faults_total{entrypoint=\"kernel_driver_step\",status=\"out_of_gas\"} 2\n\
             solo_kernel_faults_total{} 1\n\
             solo_kernel_call_duration_seconds_sum{entrypoint=\"kernel_stf_execute_block\"} 30\n\
             solo_kernel_call_duration_seconds_count{entrypoint=\"kernel_stf_execute_block\"} 10\n\
             solo_kernel_call_duration_seconds_sum 5\n\
             solo_kernel_call_duration_seconds_count 1\n",
        )
        .unwrap();
        let problems = assess(&sick, &metrics, &Limits::default());
        assert_eq!(
            problems,
            vec![
                "head 40 has not advanced for 75s (limit 60s)",
                "finalized height 20 trails the head by 20 blocks (limit 16)",
                "0 peers connected (minimum 1)",
                "1001 transactions waiting in the mempool (limit 1000)",
                "kernel_driver_step faulted 2 times (out_of_gas) since the node started",
                "? faulted 1 times (?) since the node started",
                "kernel_stf_execute_block takes 3.000s per call on average (limit 1s)",
                "? takes 5.000s per call on average (limit 1s)",
                "the pending kernel upgrade cannot be enacted: this host cannot load upgrade 0x01",
                "the chain locked in feature gates this release does not support: 0, 2",
            ]
        );
        assert_eq!(Limits::default().clone(), DEFAULT_LIMITS);
        assert!(format!("{DEFAULT_LIMITS:?}").contains("max_mempool"));
    }
}
