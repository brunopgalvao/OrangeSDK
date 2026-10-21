//! Kernel switchover (spec 06 §7) and host feature gates (spec 13 §7–§8) in
//! the node host.
//!
//! After every block it executes, the node reads the kernel's
//! `upgrade_status`. The code of a pending upgrade is fetched from chain
//! state, checked against its code hash, validated and compiled right away,
//! so that a module this host cannot run raises an alert while governance can
//! still cancel. Blocks above the activation height `H` are held until the
//! old kernel has executed and finalized `H`. The host then reads the old
//! driver's state, migrates it into the new kernel, executes the held blocks
//! with the new kernel, and delivers `Started` to the new driver ahead of
//! every queued input. A switch that cannot complete halts the node.
//!
//! The host serves a gated host function only once the chain has activated
//! its gate, and a validator's host signals the gates it supports once per
//! epoch with a transaction to the upgrade address.

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

use k256::ecdsa::SigningKey;
use solo_abi::chain::BlockHeader;
use solo_abi::types::{Block, Input, MigrateArgs, exports};
use solo_abi::{Decode, Encode};
use solo_host::hash::keccak256;
use solo_host::{Extension, Flags, Overlay, Storage};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use solo_upgrade::gates::epoch_of;
use solo_upgrade::{
    Action, PendingUpgrade, SIGNAL_GAS, UPGRADE_ADDRESS, UpgradeStatus, gate, query,
};
use solo_vm::host::{Capability, HostContext};
use solo_vm::isa::Reg;
use solo_vm::module::{Module, Program};
use solo_vm::status::{HostStatus, Termination};

use crate::extension::{NodeExtension, sign_recoverable, validator_id};
use crate::node::{Node, NodeError};

/// A host function behind a feature gate (spec 05 §7, spec 13 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatedFunction {
    /// Import name.
    pub name: &'static str,
    /// The gate that must be active for the name to resolve.
    pub gate: u8,
    /// Handle passed back on `ecall`.
    pub handle: u32,
    /// Whether the `Sandboxed` set may import it once active.
    pub sandboxed: bool,
}

/// Handle of `secp256k1_verify`; gated handles start at 200, clear of the
/// node extension's own.
pub const SECP256K1_VERIFY: u32 = 200;

/// Handle of `bls12381_fast_aggregate_verify`.
pub const BLS12381_FAST_AGGREGATE_VERIFY: u32 = 201;

/// Handle of the first precompile host function (spec 05 §4.8); the
/// others follow in the order of [`solo_host::precompiles::FUNCTIONS`].
pub const PRECOMPILE_HANDLE: u32 = solo_host::precompiles::HANDLE_BASE;

/// The precompile host function `i`, behind gate 2.
const fn precompile(i: u32) -> GatedFunction {
    GatedFunction {
        name: solo_host::precompiles::FUNCTIONS[i as usize].0,
        gate: gate::PRECOMPILES,
        handle: PRECOMPILE_HANDLE + i,
        sandboxed: true,
    }
}

/// The gated host functions this host release serves.
pub const GATED: &[GatedFunction] = &[
    GatedFunction {
        name: "secp256k1_verify",
        gate: gate::SECP256K1_VERIFY,
        handle: SECP256K1_VERIFY,
        sandboxed: true,
    },
    GatedFunction {
        name: "bls12381_fast_aggregate_verify",
        gate: gate::BLS12381_FAST_AGGREGATE_VERIFY,
        handle: BLS12381_FAST_AGGREGATE_VERIFY,
        sandboxed: true,
    },
    precompile(0),
    precompile(1),
    precompile(2),
    precompile(3),
    precompile(4),
    precompile(5),
    precompile(6),
    precompile(7),
    precompile(8),
    precompile(9),
    precompile(10),
    precompile(11),
    precompile(12),
];

/// The feature gates this host release supports: one bit per gate in [`GATED`].
pub const SUPPORTED: u64 = 1 << gate::SECP256K1_VERIFY
    | 1 << gate::BLS12381_FAST_AGGREGATE_VERIFY
    | 1 << gate::PRECOMPILES;

/// The handle of gated function `name` for `capability`, if its gate is in `active`.
#[must_use]
pub fn gated(name: &str, capability: Capability, active: u64) -> Option<u32> {
    GATED
        .iter()
        .find(|f| f.name == name)
        .filter(|f| {
            active >> f.gate & 1 == 1 && (f.sandboxed || capability == Capability::Privileged)
        })
        .map(|f| f.handle)
}

/// The node's extension with the gated host functions layered on top: a
/// gated name resolves only while its gate is in the shared active set.
pub struct GatedExtension {
    inner: NodeExtension,
    active: Rc<Cell<u64>>,
}

impl GatedExtension {
    /// Wraps `inner`; `active` is the set of gates active for the next block.
    #[must_use]
    pub fn new(inner: NodeExtension, active: Rc<Cell<u64>>) -> GatedExtension {
        GatedExtension { inner, active }
    }
}

impl<S: Storage> Extension<S> for GatedExtension {
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
        gated(name, capability, self.active.get())
            .or_else(|| <NodeExtension as Extension<S>>::resolve(&self.inner, name, capability))
    }

    fn call(
        &mut self,
        handle: u32,
        ctx: &mut HostContext<'_>,
        state: &mut Overlay<S>,
    ) -> Result<(), Termination> {
        if handle == SECP256K1_VERIFY {
            return secp256k1_verify(ctx);
        }
        if handle == BLS12381_FAST_AGGREGATE_VERIFY {
            return solo_host::gated::bls12381_fast_aggregate_verify(ctx);
        }
        if handle >= PRECOMPILE_HANDLE {
            return solo_host::precompiles::dispatch(handle, ctx);
        }
        self.inner.call(handle, ctx, state)
    }
}

fn read(ctx: &HostContext<'_>, ptr: u32, len: u32) -> Result<Vec<u8>, Termination> {
    ctx.memory
        .read(ptr, len)
        .map(<[u8]>::to_vec)
        .map_err(|_| Termination::HostError(HostStatus::MemoryFault.code()))
}

/// `secp256k1_verify(msg, sig, pubkey)`: `a0` = 0 if the 64-byte `r || s`
/// signature with low `s` is valid for the 32-byte digest under the 64-byte
/// uncompressed public key, 1 otherwise. Cost 3 000.
fn secp256k1_verify(ctx: &mut HostContext<'_>) -> Result<(), Termination> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{Signature, VerifyingKey};
    ctx.charge(3_000)?;
    let msg = read(ctx, ctx.arg32(Reg::A0), 32)?;
    let sig = read(ctx, ctx.arg32(Reg::A1), 64)?;
    let mut sec1 = vec![4];
    sec1.extend(read(ctx, ctx.arg32(Reg::A2), 64)?);
    let valid = VerifyingKey::from_sec1_bytes(&sec1)
        .ok()
        .zip(Signature::from_slice(&sig).ok())
        .is_some_and(|(k, s)| k.verify_prehash(&msg, &s).is_ok());
    ctx.set(Reg::A0, u64::from(!valid));
    Ok(())
}

/// A kernel switch the node performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    /// The activation height: the last block the old kernel executed.
    pub height: u64,
    /// Code hash of the new kernel.
    pub code_hash: [u8; 32],
    /// The old kernel's version.
    pub from_version: u32,
    /// The new kernel's version.
    pub to_version: u32,
    /// Blocks above the activation height the old driver had already
    /// finalized, executed by the new kernel at the switch.
    pub held: usize,
}

/// The node's kernel-upgrade and feature-gate state.
#[derive(Debug)]
pub struct Upgrades {
    /// The kernel's `upgrade_status` after the last block executed; `None`
    /// before the first. A kernel that does not serve the query reads as the default.
    pub status: Option<UpgradeStatus>,
    /// Code hash of the pending upgrade's module once validated and compiled.
    pub prepared: Option<[u8; 32]>,
    /// Why the pending upgrade's module cannot be prepared, while it cannot:
    /// the alert that lets governance cancel before the node would halt.
    pub alert: Option<String>,
    /// Kernel switches performed, in order.
    pub switches: Vec<Switch>,
    /// The gates this host signals and serves; [`SUPPORTED`] unless a test
    /// stands in for another host release.
    pub features: u64,
    /// Code hash and gate set of the last failed preparation, retried only
    /// when one of them changes.
    failed: Option<([u8; 32], u64)>,
    /// `(H, code hash)` once block `H` has executed with an upgrade activating at `H`.
    switch_at: Option<(u64, [u8; 32])>,
    /// Blocks above `H` the driver asked to execute before the switch.
    held: Vec<Block>,
    /// Why the node halted; every later step reports it.
    halted: Option<NodeError>,
    /// Gates active for the next block, shared with [`GatedExtension`].
    active: Rc<Cell<u64>>,
    /// A signal transaction to submit once the current step is done.
    signal: Option<Vec<u8>>,
}

impl Upgrades {
    /// Fresh state sharing `active` with the node's [`GatedExtension`].
    #[must_use]
    pub fn new(active: Rc<Cell<u64>>) -> Upgrades {
        Upgrades {
            status: None,
            prepared: None,
            alert: None,
            switches: Vec::new(),
            features: SUPPORTED,
            failed: None,
            switch_at: None,
            held: Vec::new(),
            halted: None,
            active,
            signal: None,
        }
    }

    /// Gates active for the next block that this host serves.
    #[must_use]
    pub fn active(&self) -> u64 {
        self.active.get()
    }

    /// Gates the chain has locked in that this host does not support: the
    /// alert that tells an operator to install a newer host release.
    #[must_use]
    pub fn missing_gates(&self) -> u64 {
        self.status
            .as_ref()
            .map_or(0, |s| s.gates.locked_in() & !self.features)
    }

    /// Number of blocks held for the new kernel.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Why the node halted, if it did.
    #[must_use]
    pub fn halted(&self) -> Option<&NodeError> {
        self.halted.as_ref()
    }
}

/// The legacy EIP-155 transaction with which a validator's host signals
/// `features`: to the upgrade address, no value, gas price zero.
///
/// # Panics
/// Never: signing a 32-byte digest with a valid key cannot fail.
#[must_use]
pub fn signal_tx(key: &SigningKey, chain_id: u64, nonce: u64, features: u64) -> Vec<u8> {
    let data = Action::Signal { features }.encode();
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(0, out);
        encode_uint(u128::from(SIGNAL_GAS), out);
        encode_bytes(&UPGRADE_ADDRESS, out);
        encode_uint(0, out);
        encode_bytes(&data, out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    encode_uint(u128::from(chain_id), &mut unsigned);
    encode_uint(0, &mut unsigned);
    encode_uint(0, &mut unsigned);
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let sig = sign_recoverable(key, &keccak256(&list)).expect("a digest signs");
    let strip = |b: &[u8]| b[b.iter().take_while(|x| **x == 0).count()..].to_vec();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(
        u128::from(chain_id) * 2 + 35 + u128::from(sig[64]),
        &mut signed,
    );
    encode_bytes(&strip(&sig[..32]), &mut signed);
    encode_bytes(&strip(&sig[32..64]), &mut signed);
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

impl Node {
    /// The kernel-upgrade and feature-gate state.
    #[must_use]
    pub fn upgrades(&self) -> &Upgrades {
        &self.upgrades
    }

    /// Sets the gates this host signals and serves, standing in for another
    /// host release; [`SUPPORTED`] by default.
    pub fn set_host_features(&mut self, features: u64) {
        self.upgrades.features = features;
    }

    /// Code hash of the running kernel.
    #[must_use]
    pub fn kernel_hash(&self) -> [u8; 32] {
        self.kernel
    }

    /// Whether a module loaded now could import `name` under `capability`.
    #[must_use]
    pub fn resolves(&self, name: &str, capability: Capability) -> bool {
        self.exec.resolver()(name, capability)
    }

    /// The running kernel's version (`kernel_version`, spec 06 §7.1).
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn kernel_version(&mut self) -> Result<u32, NodeError> {
        self.version_of(self.kernel)
    }

    /// The running kernel's `upgrade_status`; the default for a kernel that
    /// does not serve it.
    ///
    /// # Errors
    /// See [`NodeError`].
    pub fn upgrade_status(&mut self) -> Result<UpgradeStatus, NodeError> {
        let r = self.query(query::STATUS, &[])?;
        let status = (r.status == 0).then(|| UpgradeStatus::from_bytes(&r.body));
        status
            .transpose()
            .map(Option::unwrap_or_default)
            .map_err(|_| NodeError::Decode(query::STATUS))
    }

    /// Calls `export` of the compiled module `code_hash` against chain
    /// state, with the `Privileged` set and the kernel gas budget, as the
    /// kernel switch does: for inspecting a prepared upgrade. Writes are kept
    /// if the call halts. The call is recorded in the `solo_kernel_*`
    /// families like any other entrypoint call (spec 11 §4).
    ///
    /// # Errors
    /// [`NodeError::Kernel`] unless the call halts.
    pub fn call_module(
        &mut self,
        code_hash: [u8; 32],
        export: &'static str,
        input: &[u8],
    ) -> Result<Vec<u8>, NodeError> {
        let started = std::time::Instant::now();
        let r = self.exec.call_export(
            &code_hash,
            export,
            [0; 32],
            input,
            self.kernel_gas,
            Capability::Privileged,
            Flags::default(),
        );
        crate::telemetry::record_call(&mut self.telemetry, &mut self.exec, export, started, &r);
        if r.status == Termination::Halt {
            Ok(r.output)
        } else {
            Err(NodeError::Kernel {
                export,
                status: r.status,
            })
        }
    }

    fn version_of(&mut self, code_hash: [u8; 32]) -> Result<u32, NodeError> {
        let out = self.call_module(code_hash, exports::VERSION, &[])?;
        u32::from_bytes(&out)
            .ok()
            .ok_or(NodeError::Decode(exports::VERSION))
    }

    /// Fails with the reason the node halted, once it has.
    pub(crate) fn upgrade_halted(&self) -> Result<(), NodeError> {
        self.upgrades.halted.clone().map_or(Ok(()), Err)
    }

    /// Applies an `ExecuteBlock` effect: holds a block above the activation
    /// height of the switch due, executes any other and reads the upgrade
    /// status after it.
    pub(crate) fn execute_or_hold(&mut self, block: Block) -> Result<Option<Input>, NodeError> {
        let header = BlockHeader::from_bytes(&block.header)
            .map_err(|_| NodeError::Decode("block header"))?;
        if self
            .upgrades
            .switch_at
            .is_some_and(|(h, _)| header.height > h)
        {
            self.upgrades.held.push(block);
            return Ok(None);
        }
        let executed = self.execute_block(block)?;
        self.after_executed(header.height)?;
        Ok(Some(executed))
    }

    fn after_executed(&mut self, height: u64) -> Result<(), NodeError> {
        let status = self.upgrade_status()?;
        self.upgrades
            .active
            .set(status.gates.active_at(height + 1) & self.upgrades.features);
        self.upgrades.switch_at = status
            .pending
            .as_ref()
            .filter(|p| p.activation_height == height)
            .map(|p| (height, p.code_hash));
        if let Some(pending) = &status.pending {
            let gates = status
                .gates
                .active_at(pending.activation_height.saturating_add(1));
            self.prepare(pending, gates)?;
        } else {
            self.upgrades.prepared = None;
            self.upgrades.alert = None;
        }
        self.upgrades.signal = self.signal_for(height, &status)?;
        self.upgrades.status = Some(status);
        Ok(())
    }

    /// Validates and compiles a pending upgrade's module, resolving the gated
    /// functions of the gates that will be active once it runs; once per
    /// code hash and gate set.
    fn prepare(&mut self, pending: &PendingUpgrade, gates: u64) -> Result<(), NodeError> {
        let gates = gates & self.upgrades.features;
        let attempt = (pending.code_hash, gates);
        if self.upgrades.prepared == Some(pending.code_hash)
            || self.upgrades.failed == Some(attempt)
        {
            return Ok(());
        }
        let r = self.query(query::CODE, &pending.code_hash)?;
        let code = Vec::<u8>::from_bytes(&r.body).unwrap_or_default();
        let prepared = self
            .compile(&code, &pending.code_hash, gates)
            .and_then(|()| self.supersedes(&pending.code_hash));
        match prepared {
            Ok(()) => {
                self.upgrades.prepared = Some(pending.code_hash);
                self.upgrades.alert = None;
            }
            Err(why) => {
                self.upgrades.alert = Some(why);
                self.upgrades.failed = Some(attempt);
            }
        }
        Ok(())
    }

    fn compile(&mut self, code: &[u8], code_hash: &[u8; 32], gates: u64) -> Result<(), String> {
        // Code that does not hash to its code hash counts as no code at all.
        let code = &code[..code.len() * usize::from(keccak256(code) == *code_hash)];
        let module = {
            let resolve = self.exec.resolver();
            let imports = |name: &str| {
                resolve(name, Capability::Privileged)
                    || gated(name, Capability::Privileged, gates).is_some()
            };
            Module::parse(code, &imports)
        };
        let module = module
            .map_err(|e| format!("this host cannot load upgrade {}: {e:?}", hex(code_hash)))?;
        let program = Program::new(module, self.exec.cache_mut().cost_table());
        self.exec.cache_mut().insert_program(*code_hash, program);
        Ok(())
    }

    /// Checks that the compiled module `code_hash` has a version above the
    /// running kernel's (spec 06 §7.1): `kernel_migrate` of any other would
    /// halt every node at the activation height.
    fn supersedes(&mut self, code_hash: &[u8; 32]) -> Result<(), String> {
        let versions = self
            .kernel_version()
            .and_then(|from| Ok((from, self.version_of(*code_hash)?)));
        match versions {
            Ok((from, to)) if to > from => Ok(()),
            Ok((from, to)) => Err(format!(
                "upgrade {} is version {to}, which does not supersede the running version {from}",
                hex(code_hash)
            )),
            Err(e) => Err(format!(
                "cannot read the version of upgrade {}: {e}",
                hex(code_hash)
            )),
        }
    }

    /// Switches kernels once the old kernel has executed and finalized the
    /// activation height (spec 06 §7). Any failure halts the node.
    pub(crate) fn switch_kernel_if_due(
        &mut self,
        queue: &mut VecDeque<Input>,
    ) -> Result<(), NodeError> {
        let finalized = self.finalized.last().copied().unwrap_or(0);
        let Some((height, code_hash)) = self.upgrades.switch_at.filter(|(h, _)| finalized >= *h)
        else {
            return Ok(());
        };
        self.upgrades.switch_at = None;
        let switched = self.switch_kernel(height, code_hash, queue);
        self.upgrades.halted = switched.clone().err();
        switched
    }

    fn switch_kernel(
        &mut self,
        height: u64,
        code_hash: [u8; 32],
        queue: &mut VecDeque<Input>,
    ) -> Result<(), NodeError> {
        if self.upgrades.prepared != Some(code_hash) {
            let why = self.upgrades.alert.clone().unwrap_or_default();
            return Err(NodeError::Upgrade(format!(
                "no runnable kernel at height {height}: {why}"
            )));
        }
        let from_version = self.kernel_version()?;
        let to_version = self.version_of(code_hash)?;
        let driver_state = self.driver_state()?;
        self.call_module(
            code_hash,
            exports::MIGRATE,
            &MigrateArgs {
                from_version,
                driver_state,
            }
            .to_bytes(),
        )?;
        self.kernel = code_hash;
        self.upgrades.prepared = None;
        let held = std::mem::take(&mut self.upgrades.held);
        self.upgrades.switches.push(Switch {
            height,
            code_hash,
            from_version,
            to_version,
            held: held.len(),
        });
        self.upgrades.status = Some(self.upgrade_status()?);
        // The new driver starts first; then the results of the blocks the old
        // driver had finalized past `H`, executed now by the new kernel; then
        // whatever was already queued.
        let mut front = VecDeque::from([Input::Started {
            now_ms: self.now_ms(),
            resumed_state: None,
        }]);
        for block in held {
            front.extend(self.execute_or_hold(block)?);
        }
        front.append(queue);
        *queue = front;
        Ok(())
    }

    /// The signal transaction to send after the block at `height`, if this
    /// node is a validator whose latest signal does not cover the epoch of
    /// the next block with the features it supports.
    fn signal_for(
        &mut self,
        height: u64,
        status: &UpgradeStatus,
    ) -> Result<Option<Vec<u8>>, NodeError> {
        let epoch_blocks = status.params.epoch_blocks;
        let target = epoch_of(height + 1, epoch_blocks);
        let features = self.upgrades.features;
        let Some(key) = self.services_key().filter(|_| epoch_blocks != 0) else {
            return Ok(None);
        };
        let id = validator_id(&key);
        let due = status
            .validators
            .0
            .iter()
            .find(|v| v.id == id)
            .is_some_and(|v| {
                v.signal
                    .as_ref()
                    .is_none_or(|s| s.epoch < target || s.features != features)
            });
        if !due {
            return Ok(None);
        }
        let address: [u8; 20] = id[12..].try_into().expect("20 bytes");
        let nonce = self.account(&address)?.nonce;
        let chain_id = self.chain_id()?;
        Ok(Some(signal_tx(&key, chain_id, nonce, features)))
    }

    /// Submits the signal transaction the last executed block called for.
    /// Signalling is best effort: one the node cannot submit now is rebuilt
    /// after the next block.
    pub(crate) fn send_gate_signal(&mut self) {
        if let Some(raw) = self.upgrades.signal.take() {
            let _ = self.submit(&raw);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::from("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
