//! Call frames and nested invoke (spec 05 §4.4).

use std::collections::HashMap;
use std::sync::Arc;

use solo_jit::Compiled;
use solo_vm::host::{Capability, Host, HostContext};
use solo_vm::interp::{Instance, InstanceError};
use solo_vm::module::Program;
use solo_vm::status::{HostStatus, Termination};

use crate::abi;
use crate::cache::ModuleCache;
use crate::storage::{Overlay, Storage};

/// Lowest handle an [`Extension`] may use; the built-in ABI owns the rest.
pub const EXTENSION_HANDLE_BASE: u32 = 100;

/// Host functions supplied by whoever embeds the executor: the privileged
/// functions of spec 05 that need node state (commitments, time, timers,
/// persistence, network). Handles are `EXTENSION_HANDLE_BASE` and above.
pub trait Extension<S: Storage> {
    /// Resolves a name under a capability set to a handle, or `None`.
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32>;

    /// Performs the function.
    ///
    /// # Errors
    /// A terminating status (spec 05 §6).
    fn call(
        &mut self,
        handle: u32,
        ctx: &mut HostContext<'_>,
        state: &mut Overlay<S>,
    ) -> Result<(), Termination>;
}

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
    extension: Option<Box<dyn Extension<S>>>,
    last_position: Option<([u8; 32], u32, usize)>,
    backend: Backend,
    native: HashMap<[u8; 32], Arc<Compiled>>,
}

/// Which backend runs instances. Results are identical (spec 07 §4); only
/// speed differs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    /// The reference interpreter.
    #[default]
    Interpreter,
    /// Native code from `solo-jit`, compiled once per code hash. Falls back
    /// to the interpreter on targets without a native backend.
    Native,
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
            extension: None,
            last_position: None,
            backend: Backend::Interpreter,
            native: HashMap::new(),
        }
    }

    /// Where the most recent call ended: its code hash, block index and
    /// instruction index. With a module's debug map this names the faulting
    /// instruction in the original binary.
    #[must_use]
    pub fn last_position(&self) -> Option<([u8; 32], u32, usize)> {
        self.last_position
    }

    /// Installs the extension that serves handles from [`EXTENSION_HANDLE_BASE`] up.
    pub fn set_extension(&mut self, extension: Box<dyn Extension<S>>) {
        self.extension = Some(extension);
    }

    /// The installed extension, if any.
    pub fn extension_mut(&mut self) -> Option<&mut (dyn Extension<S> + 'static)> {
        self.extension.as_deref_mut()
    }

    /// Resolves an import against the built-in ABI and the extension; the
    /// shape [`ModuleCache::insert`] takes.
    pub fn resolver(&self) -> impl Fn(&str, Capability) -> bool + '_ {
        move |name, capability| self.resolve(name, capability).is_some()
    }

    /// Loads a module into the cache, resolving imports against this executor.
    ///
    /// # Errors
    /// [`crate::cache::LoadError`] if the module is invalid or imports something unavailable.
    pub fn load(
        &mut self,
        bytes: &[u8],
        capability: Capability,
    ) -> Result<[u8; 32], crate::cache::LoadError> {
        let abi_ok = |name: &str, cap: Capability| abi::resolve(name, cap).is_some();
        let ext_ok = |name: &str, cap: Capability| {
            self.extension
                .as_ref()
                .is_some_and(|e| e.resolve(name, cap).is_some())
        };
        let resolver = |name: &str, cap: Capability| abi_ok(name, cap) || ext_ok(name, cap);
        let hash = crate::hash::keccak256(bytes);
        if self.cache.get(&hash).is_none() {
            let module = solo_vm::module::Module::parse(bytes, &|name| resolver(name, capability))
                .map_err(crate::cache::LoadError::Invalid)?;
            let program = solo_vm::module::Program::new(module, self.cache.cost_table());
            self.cache.insert_program(hash, program);
        }
        Ok(hash)
    }

    /// Chooses the backend for every later call.
    pub fn set_backend(&mut self, backend: Backend) {
        self.backend = backend;
    }

    /// Native code for a cached program, compiled on first use; `None` where
    /// the target has no native backend.
    fn native_code(&mut self, hash: &[u8; 32], program: &Program) -> Option<Arc<Compiled>> {
        if let Some(code) = self.native.get(hash) {
            return Some(Arc::clone(code));
        }
        let code = Arc::new(Compiled::new(program).ok()?);
        self.native.insert(*hash, Arc::clone(&code));
        Some(code)
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
        let native = match self.backend {
            Backend::Native => self.native_code(code_hash, &program),
            Backend::Interpreter => None,
        };
        // Both backends report (status, gas left, position); spec 07 §4
        // holds them to identical values.
        let started = match &native {
            Some(code) => solo_jit::Instance::new(code, self, capability, export, &[], gas_limit)
                .map(|mut i| (i.run(self), i.gas(), i.position())),
            None => Instance::new(&program, self, capability, export, &[], gas_limit)
                .map(|mut i| (i.run(self), i.gas(), i.position())),
        };
        let (status, gas_used, ran) = match started {
            Ok((status, gas, (block, index))) => {
                let used = gas_limit - gas.max(0);
                self.last_position = Some((*code_hash, block, index));
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
        abi::resolve(name, capability).or_else(|| {
            self.extension
                .as_ref()
                .and_then(|e| e.resolve(name, capability))
        })
    }

    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        if handle < EXTENSION_HANDLE_BASE {
            return abi::dispatch(self, handle, ctx);
        }
        match self.extension.as_mut() {
            Some(ext) => ext.call(handle, ctx, &mut self.state),
            None => Err(Termination::HostError(HostStatus::Unavailable.code())),
        }
    }
}
