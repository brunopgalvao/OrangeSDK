//! Modules invoked from chain state (spec 05 §4.4.1).
//!
//! A module the host has not been handed explicitly is looked up under
//! [`CODE_PREFIX`] ‖ code hash in the state visible to the caller, so a kernel
//! that writes module bytes there can invoke them in the same call. A module
//! found there runs only while its bytes are still there: a cached copy is
//! never trusted past the state that justified it, because another node may
//! not have it cached.

use std::sync::Arc;

use solo_vm::host::Capability;
use solo_vm::module::Program;

use crate::executor::Executor;
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

impl<S: Storage> Executor<S> {
    /// The program to run for `code_hash` and the gas its loading costs the
    /// callee: an explicitly loaded program for free, otherwise the module
    /// under [`code_key`] if its bytes hash to `code_hash` and validate for
    /// `capability`. `None` when neither exists.
    pub(crate) fn program_for(
        &mut self,
        code_hash: &[u8; 32],
        capability: Capability,
    ) -> Option<(Arc<Program>, i64)> {
        if !self.from_state.contains_key(code_hash)
            && let Some(program) = self.cache.get(code_hash)
        {
            return Some((program, 0));
        }
        let bytes = self.state.get(&code_key(code_hash))?;
        let cost = load_cost(bytes.len());
        if self.from_state.get(code_hash) == Some(&bytes) {
            return self.cache.get(code_hash).map(|p| (p, cost));
        }
        if crate::hash::keccak256(&bytes) != *code_hash {
            return None;
        }
        let program = {
            let resolver = self.resolver();
            let module =
                solo_vm::module::Module::parse(&bytes, &|name| resolver(name, capability)).ok()?;
            Program::new(module, self.cache.cost_table())
        };
        self.cache.insert_program(*code_hash, program);
        self.from_state.insert(*code_hash, bytes);
        self.cache.get(code_hash).map(|p| (p, cost))
    }
}
