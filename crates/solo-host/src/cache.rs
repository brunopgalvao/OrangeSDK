//! Compiled modules keyed by code hash (spec 03 §1, 05 §4.4).

use std::collections::HashMap;
use std::sync::Arc;

use solo_vm::gas::CostTable;
use solo_vm::host::Capability;
use solo_vm::module::{Module, Program, ValidationError};

use crate::hash::keccak256;

/// Why a module could not be added to the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// Validation failed (spec 03 §7).
    Invalid(ValidationError),
}

/// Validated, cost-annotated programs by code hash.
#[derive(Debug)]
pub struct ModuleCache {
    programs: HashMap<[u8; 32], Arc<Program>>,
    cost_table: CostTable,
}

impl ModuleCache {
    /// An empty cache computing block costs with `cost_table`.
    #[must_use]
    pub fn new(cost_table: CostTable) -> ModuleCache {
        ModuleCache {
            programs: HashMap::new(),
            cost_table,
        }
    }

    /// Validates `bytes` as a module whose imports `resolver` can satisfy for
    /// `capability`, stores it, and returns its code hash. Re-inserting the
    /// same bytes is a no-op.
    ///
    /// # Errors
    /// [`LoadError::Invalid`] if the module fails validation.
    pub fn insert(
        &mut self,
        bytes: &[u8],
        capability: Capability,
        resolver: &dyn Fn(&str, Capability) -> bool,
    ) -> Result<[u8; 32], LoadError> {
        let hash = keccak256(bytes);
        if !self.programs.contains_key(&hash) {
            let module = Module::parse(bytes, &|name| resolver(name, capability))
                .map_err(LoadError::Invalid)?;
            self.programs
                .insert(hash, Arc::new(Program::new(module, self.cost_table)));
        }
        Ok(hash)
    }

    /// The program with this code hash, if cached.
    #[must_use]
    pub fn get(&self, hash: &[u8; 32]) -> Option<Arc<Program>> {
        self.programs.get(hash).cloned()
    }

    /// Number of cached programs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.programs.len()
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }
}

impl Default for ModuleCache {
    /// An empty cache using cost table version 1.
    fn default() -> Self {
        ModuleCache::new(CostTable::V1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solo_vm::builder::ModuleBuilder;
    use solo_vm::isa::Instruction;

    #[test]
    fn insert_get_and_dedupe() {
        let mut cache = ModuleCache::new(CostTable::V1);
        assert!(cache.is_empty());
        let mut b = ModuleBuilder::new();
        b.block(&[Instruction::Halt]);
        let bytes = b.export("main", 0).build();
        let h1 = cache
            .insert(&bytes, Capability::Sandboxed, &|_, _| true)
            .unwrap();
        let h2 = cache
            .insert(&bytes, Capability::Sandboxed, &|_, _| true)
            .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1, keccak256(&bytes));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&h1).unwrap().block_costs, vec![1]);
        assert!(cache.get(&[0; 32]).is_none());
        assert_eq!(
            cache.insert(b"not a module", Capability::Privileged, &|_, _| true),
            Err(LoadError::Invalid(ValidationError::BadMagic))
        );
        let mut b = ModuleBuilder::new();
        b.import("missing");
        b.block(&[Instruction::Halt]);
        let bytes = b.export("main", 0).build();
        assert_eq!(
            cache.insert(&bytes, Capability::Sandboxed, &|_, _| false),
            Err(LoadError::Invalid(ValidationError::UnresolvedImport))
        );
        assert!(format!("{cache:?}").contains("ModuleCache"));
        assert!(ModuleCache::default().is_empty());
    }
}
