//! Call frames and nested invoke (spec 05 §4.4).

use std::sync::Arc;

use solo_vm::host::{Capability, Host, HostContext};
use solo_vm::interp::{Instance, InstanceError};
use solo_vm::module::Program;
use solo_vm::status::{HostStatus, Termination};

use crate::abi;
use crate::cache::ModuleCache;
use crate::storage::{Overlay, Storage};

/// Flags of an `invoke` (spec 05 §4.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// Run the callee with the `Privileged` set. Only honoured for privileged callers.
    pub privileged: bool,
    /// Forbid the callee any state change.
    pub static_call: bool,
}

impl Flags {
    /// Decodes the `flags` argument register.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Flags {
        Flags {
            privileged: bits & 1 != 0,
            static_call: bits & 2 != 0,
        }
    }
}

/// The outcome of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResult {
    /// How the callee ended, or why it never started.
    pub status: Termination,
    /// The callee's output blob.
    pub output: Vec<u8>,
    /// Gas consumed out of the limit.
    pub gas_used: u64,
    /// Whether an instance ran at all. `false` means `status` is a
    /// `HostError` from before instantiation: unknown code or export, the
    /// nesting limit, or a bad gas limit.
    pub started: bool,
}

impl CallResult {
    /// The status code `invoke` reports to a caller for this result (spec 05 §4.4, §6).
    #[must_use]
    pub const fn invoke_status(&self) -> HostStatus {
        match (self.started, self.status) {
            (_, Termination::Halt) => HostStatus::Ok,
            (false, Termination::HostError(code)) => match code {
                2 => HostStatus::NotFound,
                4 => HostStatus::DepthExceeded,
                _ => HostStatus::InvalidArgument,
            },
            (true, Termination::HostError(3)) => HostStatus::StaticViolation,
            _ => HostStatus::CalleeTrapped,
        }
    }
}

/// An open storage iterator: its snapshot and position.
pub(crate) type Iter = (Vec<(Vec<u8>, Vec<u8>)>, usize);

/// One active call.
pub(crate) struct Frame {
    pub(crate) namespace: [u8; 32],
    pub(crate) capability: Capability,
    pub(crate) static_call: bool,
    pub(crate) input: Vec<u8>,
    pub(crate) output: Vec<u8>,
    pub(crate) last_callee_output: Vec<u8>,
    pub(crate) iterators: Vec<Iter>,
}

/// Executes programs from a cache against an overlaid store, serving the host
/// ABI to every instance it runs.
pub struct Executor<S: Storage> {
    pub(crate) cache: ModuleCache,
    pub(crate) state: Overlay<S>,
    pub(crate) frames: Vec<Frame>,
    pub(crate) logs: Vec<(u32, Vec<u8>)>,
    pub(crate) metrics: Vec<(String, i64, u32)>,
    max_depth: usize,
}

/// Default nesting limit (spec 05 §4.4).
pub const MAX_DEPTH: usize = 1024;

impl<S: Storage> Executor<S> {
    /// An executor over `storage` with an empty module cache.
    pub fn new(cache: ModuleCache, storage: S) -> Executor<S> {
        Executor {
            cache,
            state: Overlay::new(storage),
            frames: Vec::new(),
            logs: Vec::new(),
            metrics: Vec::new(),
            max_depth: MAX_DEPTH,
        }
    }

    /// Lowers the nesting limit; for tests and constrained hosts.
    pub fn set_max_depth(&mut self, depth: usize) {
        self.max_depth = depth;
    }

    /// The module cache.
    pub fn cache_mut(&mut self) -> &mut ModuleCache {
        &mut self.cache
    }

    /// The state, with any open layers.
    pub fn state(&self) -> &Overlay<S> {
        &self.state
    }

    /// Mutable state, for hosts that seed or inspect it between calls.
    pub fn state_mut(&mut self) -> &mut Overlay<S> {
        &mut self.state
    }

    /// Log lines emitted so far, as `(level, bytes)`.
    pub fn logs(&self) -> &[(u32, Vec<u8>)] {
        &self.logs
    }

    /// Metrics emitted so far, as `(name, value, kind)`.
    pub fn metrics(&self) -> &[(String, i64, u32)] {
        &self.metrics
    }

    /// Calls the `main` export of `code_hash`.
    pub fn call(
        &mut self,
        code_hash: &[u8; 32],
        namespace: [u8; 32],
        input: &[u8],
        gas_limit: i64,
        capability: Capability,
        flags: Flags,
    ) -> CallResult {
        self.call_export(
            code_hash, "main", namespace, input, gas_limit, capability, flags,
        )
    }

    /// Calls an export of a cached program in a fresh instance and frame.
    /// Storage writes are kept on `Halt` and discarded otherwise.
    ///
    /// Failures to start the call are reported as a `HostError` status with
    /// no gas used and `started == false`: `NotFound` for an unknown code hash
    /// or export, `DepthExceeded` at the nesting limit, `InvalidArgument` for a
    /// bad gas limit.
    ///
    /// # Panics
    /// Never; the frame pushed before the call is always there to pop.
    #[allow(clippy::too_many_arguments)]
    pub fn call_export(
        &mut self,
        code_hash: &[u8; 32],
        export: &str,
        namespace: [u8; 32],
        input: &[u8],
        gas_limit: i64,
        capability: Capability,
        flags: Flags,
    ) -> CallResult {
        let fail = |status: HostStatus| CallResult {
            status: Termination::HostError(status.code()),
            output: Vec::new(),
            gas_used: 0,
            started: false,
        };
        if self.frames.len() >= self.max_depth {
            return fail(HostStatus::DepthExceeded);
        }
        let Some(program): Option<Arc<Program>> = self.cache.get(code_hash) else {
            return fail(HostStatus::NotFound);
        };
        let parent_static = self.frames.last().is_some_and(|f| f.static_call);
        self.frames.push(Frame {
            namespace,
            capability,
            static_call: flags.static_call || parent_static,
            input: input.to_vec(),
            output: Vec::new(),
            last_callee_output: Vec::new(),
            iterators: Vec::new(),
        });
        self.state.push();
        let started = Instance::new(&program, self, capability, export, &[], gas_limit);
        let (status, gas_used, ran) = match started {
            Ok(mut instance) => {
                let status = instance.run(self);
                let used = gas_limit - instance.gas().max(0);
                (status, u64::try_from(used).unwrap_or(0), true)
            }
            Err(InstanceError::NoSuchExport | InstanceError::UnresolvedImport(_)) => (
                Termination::HostError(HostStatus::NotFound.code()),
                0,
                false,
            ),
            Err(InstanceError::GasLimit) => (
                Termination::HostError(HostStatus::InvalidArgument.code()),
                0,
                false,
            ),
        };
        let frame = self.frames.pop().expect("frame pushed above");
        if status == Termination::Halt {
            self.state.commit();
        } else {
            self.state.discard();
        }
        CallResult {
            status,
            output: frame.output,
            gas_used,
            started: ran,
        }
    }

    pub(crate) fn frame(&mut self) -> &mut Frame {
        self.frames
            .last_mut()
            .expect("host functions run inside a frame")
    }
}

impl<S: Storage> Host for Executor<S> {
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32> {
        abi::resolve(name, capability)
    }

    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        abi::dispatch(self, handle, ctx)
    }
}
