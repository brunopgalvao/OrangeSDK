//! What a node records about itself (spec 11): the hooks the driver loop
//! and the transport call, and the views behind `GET /metrics` and
//! `GET /status`. Consensus-ignored throughout: nothing here feeds back
//! into a kernel call.

use std::time::Instant;

use orange_host::{CallResult, Executor};

use crate::state::ChainState;
use orange_metrics::{NodeMetrics, Origin, PendingUpgrade, Status, VERSION};
use orange_vm::host::Capability;
use orange_vm::status::Termination;

use crate::net::Frame;
use crate::node::{Node, NodeError};

/// The `status` label of `orange_kernel_faults_total` for a termination.
#[must_use]
pub fn fault_label(status: Termination) -> &'static str {
    match status {
        Termination::Halt => "halt",
        Termination::OutOfGas => "out_of_gas",
        Termination::Trap => "trap",
        Termination::MemoryFault => "memory_fault",
        Termination::InvalidJump => "invalid_jump",
        Termination::HostError(_) => "host_error",
        Termination::StepLimit => "step_limit",
    }
}

/// Records one kernel entrypoint call: duration, gas, fault, and whatever
/// the call emitted through `metric_emit` and `log_emit`.
pub(crate) fn record_call(
    telemetry: &mut NodeMetrics,
    exec: &mut Executor<ChainState>,
    export: &str,
    started: Instant,
    r: &CallResult,
) {
    let fault = (r.status != Termination::Halt).then(|| fault_label(r.status));
    telemetry.kernel_call(export, started.elapsed(), r.gas_used, fault);
    for (name, value, kind, capability) in exec.take_metrics() {
        let origin = match capability {
            Capability::Privileged => Origin::Kernel,
            Capability::Sandboxed => Origin::Sandboxed,
        };
        telemetry.emitted(origin, name.as_bytes(), value, kind);
    }
    telemetry.kernel_logs(exec.logs());
}

impl Frame {
    /// The `kind` label of `orange_p2p_frames_total`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Frame::Hello { .. } => "hello",
            Frame::Message { .. } => "message",
            Frame::Tx { .. } => "tx",
            Frame::Request { .. } => "request",
            Frame::Response { .. } => "response",
            Frame::SyncRequest { .. } => "sync_request",
            Frame::SyncResponse { .. } => "sync_response",
            Frame::GetPeers => "get_peers",
            Frame::Peers { .. } => "peers",
            Frame::Auth { .. } => "auth",
        }
    }
}

impl Node {
    /// The node's metrics.
    #[must_use]
    pub fn telemetry(&self) -> &NodeMetrics {
        &self.telemetry
    }

    /// The node's metrics, for a host component that records into them.
    pub fn telemetry_mut(&mut self) -> &mut NodeMetrics {
        &mut self.telemetry
    }

    /// The chain id for telemetry: asked of the kernel until it first
    /// answers, then kept (spec 11 section 2), so that a scrape does not run
    /// a kernel call once the id is known.
    fn telemetry_chain_id(&mut self) -> Result<u64, NodeError> {
        if let Some(id) = self.telemetry.chain_id() {
            return Ok(id);
        }
        let id = self.chain_id()?;
        self.telemetry.set_chain_id(id);
        Ok(id)
    }

    /// Refreshes the gauges read at scrape time (chain id, mempool, timers,
    /// head age, upgrade alerts) and renders every family: the body of `GET /metrics`.
    pub fn metrics_text(&mut self) -> String {
        // Without a chain id the family stays empty; the rest still renders.
        self.telemetry_chain_id().ok();
        let (count, bytes) = (self.mempool().len(), self.mempool().bytes());
        let timers = self.timers().len();
        self.telemetry.refresh(count, bytes, timers);
        if let Some(stats) = self.exec.state().base().stats() {
            self.telemetry.store(
                stats.size_bytes,
                stats.write_bytes,
                stats.versions,
                stats.nodes,
            );
        }
        let upgrades = &self.upgrades;
        self.telemetry
            .upgrade(upgrades.alert.is_some(), upgrades.missing_gates());
        let status = upgrades.status.as_ref();
        self.telemetry.kernel_state(
            status.map_or(0, |s| s.version),
            status
                .and_then(|s| s.pending.as_ref())
                .map_or(0, |p| p.activation_height),
            upgrades.active(),
            upgrades.features,
        );
        self.telemetry.render()
    }

    /// The body of `GET /status`.
    ///
    /// # Errors
    /// If the kernel cannot answer the chain id query.
    pub fn status(&mut self) -> Result<Status, NodeError> {
        let chain_id = self.telemetry_chain_id()?;
        let peers = self.telemetry.peers();
        Ok(Status {
            version: VERSION.to_owned(),
            chain_id,
            chain_name: self.chain_name(),
            head: self.telemetry.head(),
            head_age_seconds: self.telemetry.head_age_seconds(),
            finalized: self.telemetry.finalized(),
            p2p: peers.is_some(),
            peers: peers.unwrap_or(0),
            mempool: self.mempool().len() as u64,
            uptime_seconds: self.telemetry.uptime_seconds(),
            validator: self.validator_id(),
            upgrade_alert: self.upgrades.alert.clone(),
            missing_gates: self.upgrades.missing_gates(),
            kernel_version: self.upgrades.status.as_ref().map_or(0, |s| s.version),
            kernel_hash: self.kernel,
            active_gates: self.upgrades.active(),
            pending_upgrade: self
                .upgrades
                .status
                .as_ref()
                .and_then(|s| s.pending.as_ref())
                .map(|p| PendingUpgrade {
                    code_hash: p.code_hash,
                    activation_height: p.activation_height,
                }),
            sync_alert: self.sync_alert(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orange_host::{Flags, ModuleCache};
    use orange_metrics::node::{EMITTED_COUNTER, KERNEL_CALL_SECONDS, KERNEL_FAULTS, KERNEL_LOGS};
    use orange_vm::builder::ModuleBuilder;
    use orange_vm::isa::{Instruction, Reg};

    /// A module whose `main` emits counter `hello` += 7 and an info log line.
    fn emitter() -> Vec<u8> {
        let li = |rd: Reg, imm: i64| Instruction::Li { rd, imm };
        let mut b = ModuleBuilder::new().rodata(b"hello");
        b.import("metric_emit");
        b.import("log_emit");
        b.block(&[
            li(Reg::A0, 0x1_0000),
            li(Reg::A1, 5),
            li(Reg::A2, 7),
            li(Reg::A3, 0),
            Instruction::Ecall { import: 0 },
            li(Reg::A0, 2),
            li(Reg::A1, 0x1_0000),
            li(Reg::A2, 5),
            Instruction::Ecall { import: 1 },
            Instruction::Halt,
        ]);
        b.export("main", 0).build()
    }

    #[test]
    fn calls_record_what_the_instance_emitted() {
        let mut exec = Executor::new(
            ModuleCache::default(),
            ChainState::open(&crate::state::StoreConfig::Memory).unwrap(),
        );
        let mut telemetry = NodeMetrics::new();
        let hash = exec.load(&emitter(), Capability::Sandboxed).unwrap();
        for (capability, gas) in [
            (Capability::Privileged, 100_000),
            (Capability::Sandboxed, 100_000),
            (Capability::Sandboxed, 3),
        ] {
            let started = Instant::now();
            let r = exec.call(&hash, [0; 32], b"", gas, capability, Flags::default());
            record_call(&mut telemetry, &mut exec, "main", started, &r);
        }
        let reg = telemetry.registry();
        assert_eq!(reg.value(&EMITTED_COUNTER, &["kernel", "hello"]), Some(7.0));
        assert_eq!(
            reg.value(&EMITTED_COUNTER, &["sandboxed", "hello"]),
            Some(7.0)
        );
        assert_eq!(reg.value(&KERNEL_LOGS, &["info"]), Some(2.0));
        assert_eq!(
            reg.value(&KERNEL_FAULTS, &["main", "out_of_gas"]),
            Some(1.0)
        );
        assert_eq!(reg.histogram(&KERNEL_CALL_SECONDS, &["main"]).unwrap().0, 3);
        assert!(exec.metrics().is_empty());
    }

    #[test]
    fn labels() {
        let cases = [
            (Termination::Halt, "halt"),
            (Termination::OutOfGas, "out_of_gas"),
            (Termination::Trap, "trap"),
            (Termination::MemoryFault, "memory_fault"),
            (Termination::InvalidJump, "invalid_jump"),
            (Termination::HostError(8), "host_error"),
            (Termination::StepLimit, "step_limit"),
        ];
        for (status, label) in cases {
            assert_eq!(fault_label(status), label);
        }
        let frames = [
            (
                Frame::Hello {
                    version: 1,
                    id: [0; 32],
                    chain_id: 1,
                    genesis: [0; 32],
                    nonce: [0; 32],
                    ephemeral: [0; 33],
                },
                "hello",
            ),
            (Frame::Auth { signature: [0; 65] }, "auth"),
            (
                Frame::Message {
                    topic: 0,
                    payload: vec![],
                },
                "message",
            ),
            (Frame::Tx { raw: vec![] }, "tx"),
            (
                Frame::Request {
                    request_id: 0,
                    payload: vec![],
                },
                "request",
            ),
            (
                Frame::Response {
                    request_id: 0,
                    payload: vec![],
                },
                "response",
            ),
        ];
        for (frame, kind) in frames {
            assert_eq!(frame.kind(), kind);
        }
    }
}
