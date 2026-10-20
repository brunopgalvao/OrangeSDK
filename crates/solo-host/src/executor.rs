//! Call frames and nested invoke (spec 05 §4.4).

use std::collections::HashMap;
use std::sync::Arc;

use solo_jit::{Compiled, Options};
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
    pub(crate) metrics: Vec<(String, i64, u32, Capability)>,
    max_depth: usize,
    extension: Option<Box<dyn Extension<S>>>,
    last_position: Option<([u8; 32], u32, usize)>,
    backend: Backend,
    /// The outcome of the one compile attempt per code hash: native code, or
    /// `None` when compilation failed and the interpreter runs it.
    native: HashMap<[u8; 32], Option<Arc<Compiled>>>,
    native_stats: NativeStats,
    native_budget: usize,
}

/// Default bound on the native code an executor keeps, in bytes.
pub const NATIVE_CODE_BUDGET: usize = 256 << 20;

/// What the native backend has done so far.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeStats {
    /// Compile attempts: at most one per code hash, failures included.
    pub attempts: usize,
    /// Attempts that produced native code.
    pub compiled: usize,
    /// Bytes of native code held, never more than the budget.
    pub code_bytes: usize,
}

/// Which backend runs instances. Results are identical (spec 07 §4); only
/// speed differs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    /// The reference interpreter.
    #[default]
    Interpreter,
    /// Native code from `solo-jit`, compiled at most once per code hash.
    /// The interpreter runs a program instead when the target has no native
    /// backend, the program does not compile, or its code would take the
    /// executor past its native code budget; that outcome is cached too.
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
            native_stats: NativeStats::default(),
            native_budget: NATIVE_CODE_BUDGET,
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

    /// Bounds the native code this executor keeps (default
    /// [`NATIVE_CODE_BUDGET`]). Programs whose code would not fit run on the
    /// interpreter; code already compiled stays.
    pub fn set_native_code_budget(&mut self, bytes: usize) {
        self.native_budget = bytes;
    }

    /// Native backend counters.
    #[must_use]
    pub fn native_stats(&self) -> NativeStats {
        self.native_stats
    }

    /// Whether the program `hash` runs natively: `None` before its first
    /// call under [`Backend::Native`], then the cached outcome.
    #[must_use]
    pub fn runs_natively(&self, hash: &[u8; 32]) -> Option<bool> {
        self.native.get(hash).map(Option::is_some)
    }

    /// Native code for a cached program, compiled on first use; `None` when
    /// the interpreter must run it. Each hash is attempted once, so a
    /// program that fails to compile never pays for code generation again.
    fn native_code(&mut self, hash: &[u8; 32], program: &Program) -> Option<Arc<Compiled>> {
        if let Some(code) = self.native.get(hash) {
            return code.clone();
        }
        let options = Options {
            code_limit: self
                .native_budget
                .saturating_sub(self.native_stats.code_bytes),
            ..Options::default()
        };
        let code = Compiled::with_options(program, options).ok().map(Arc::new);
        self.native_stats.attempts += 1;
        if let Some(code) = &code {
            self.native_stats.compiled += 1;
            self.native_stats.code_bytes += code.code_size();
        }
        self.native.insert(*hash, code.clone());
        code
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

    /// Metrics emitted since the last [`Executor::take_metrics`], as
    /// `(name, value, kind, capability of the emitting instance)`.
    pub fn metrics(&self) -> &[(String, i64, u32, Capability)] {
        &self.metrics
    }

    /// The emitted metrics, drained, so a long-running host does not keep them.
    pub fn take_metrics(&mut self) -> Vec<(String, i64, u32, Capability)> {
        std::mem::take(&mut self.metrics)
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
