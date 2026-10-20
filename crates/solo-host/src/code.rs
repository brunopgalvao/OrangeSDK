//! Modules invoked from chain state (spec 05 §4.4.1).
//!
//! A module the host has not been handed explicitly is looked up under
//! [`CODE_PREFIX`] ‖ code hash in the state visible to the caller, so a kernel
//! that writes module bytes there can invoke them in the same call. A module
//! found there runs only while its bytes are still there: a cached copy is
//! never trusted past the state that justified it, because another node may
//! not have it cached.

use std::sync::Arc;

use solo_vm::host::{Capability, Host};
use solo_vm::module::Program;
use solo_vm::status::{HostStatus, Termination};

use crate::executor::{CallResult, Executor};
use crate::storage::Storage;

/// Prefix of the chain-state key that holds a module's bytes, followed by
/// its 32-byte code hash.
pub const CODE_PREFIX: &[u8] = b"code/";

/// The chain-state key of the module with `code_hash`.
#[must_use]
pub fn code_key(code_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(CODE_PREFIX.len() + 32);
    key.extend_from_slice(CODE_PREFIX);
    key.extend_from_slice(code_hash);
    key
}

/// VM gas charged to the callee for loading `len` bytes of module from
/// chain state: one per started 32 bytes, on every call.
#[must_use]
pub fn load_cost(len: usize) -> i64 {
    i64::try_from(len.div_ceil(32)).unwrap_or(i64::MAX)
}

/// A call that ends before instantiating with `status`, having used `gas_used`.
fn unstarted(status: HostStatus, gas_used: i64) -> CallResult {
    CallResult {
        status: Termination::HostError(status.code()),
        output: Vec::new(),
        gas_used: gas_used.unsigned_abs(),
        started: false,
    }
}

impl<S: Storage> Executor<S> {
    /// The program to run for `code_hash` under `capability` with
    /// `gas_limit`, and the gas its loading costs the callee: an explicitly
    /// loaded program for free, otherwise the module under [`code_key`].
    ///
    /// A module from state is paid for before the host does any work on its
    /// bytes, and the same way whether or not this host has it cached
    /// (spec 05 §4.4.1): a limit the VM rejects fails with `InvalidArgument`,
    /// one below the load cost ends with `OutOfGas`, and bytes that do not
    /// hash to `code_hash` or validate for `capability` fail with `NotFound`
    /// having used the load cost. The `Err` is the result of such a call.
    pub(crate) fn program_for(
        &mut self,
        code_hash: &[u8; 32],
        capability: Capability,
        gas_limit: i64,
    ) -> Result<(Arc<Program>, i64), CallResult> {
        if !self.from_state.contains_key(code_hash)
            && let Some(program) = self.cache.get(code_hash)
        {
            return Ok((program, 0));
        }
        let Some(bytes) = self.state.get(&code_key(code_hash)) else {
            return Err(unstarted(HostStatus::NotFound, 0));
        };
        if !(0..=solo_vm::gas::MAX_GAS_LIMIT).contains(&gas_limit) {
            return Err(unstarted(HostStatus::InvalidArgument, 0));
        }
        let cost = load_cost(bytes.len());
        if gas_limit < cost {
            return Err(CallResult {
                status: Termination::OutOfGas,
                output: Vec::new(),
                gas_used: gas_limit.unsigned_abs(),
                started: true,
            });
        }
        let cached = (self.from_state.get(code_hash) == Some(&bytes))
            .then(|| self.cache.get(code_hash))
            .flatten();
        let program = cached.or_else(|| self.parse_from_state(code_hash, bytes));
        // A cached program may have been validated for a wider set than
        // this call's, so its imports are checked for this one every time.
        match program {
            Some(p)
                if p.module
                    .imports
                    .iter()
                    .all(|n| self.resolve(n, capability).is_some()) =>
            {
                Ok((p, cost))
            }
            _ => Err(unstarted(HostStatus::NotFound, cost)),
        }
    }

    /// Parses `bytes`, found under the key of `code_hash`, and caches them if
    /// they hash to it and validate for some capability set.
    fn parse_from_state(&mut self, code_hash: &[u8; 32], bytes: Vec<u8>) -> Option<Arc<Program>> {
        if crate::hash::keccak256(&bytes) != *code_hash {
            return None;
        }
        let program = {
            let resolver = self.resolver();
            // The privileged set contains the sandboxed one.
            let module = solo_vm::module::Module::parse(&bytes, &|name| {
                resolver(name, Capability::Privileged)
            })
            .ok()?;
            Program::new(module, self.cache.cost_table())
        };
        self.cache.insert_program(*code_hash, program);
        self.from_state.insert(*code_hash, bytes);
        self.cache.get(code_hash)
    }
}
