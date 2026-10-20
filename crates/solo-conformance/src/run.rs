//! Running a case: the conformance guest on the Solo VM, with the post-state
//! read back from the storage the kernel's state code wrote.

use solo_abi::chain::{Account as Stored, keys};
use solo_abi::conformance::{Case, EXPORT, Outcome};
use solo_abi::{Decode, Encode};
use solo_host::{Backend, Executor, Flags, MemStorage, ModuleCache, Overlay};
use solo_vm::host::Capability;
use solo_vm::status::Termination;

use crate::fixture::{Account, State};

/// VM gas for one case: far more than any state test needs, so a case ends
/// by its own EVM gas limit, never by the VM's.
pub const CASE_GAS: i64 = 1 << 50;

/// What a case did on the VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executed {
    /// The guest's report.
    pub outcome: Outcome,
    /// The state left in storage.
    pub post: State,
}

/// The conformance guest loaded into an executor.
pub struct Runner {
    exec: Executor<MemStorage>,
    guest: [u8; 32],
    backend: Backend,
}

impl Runner {
    /// Recompiles the guest ELF and loads it as the kernel is loaded:
    /// privileged, with bare storage keys.
    ///
    /// # Errors
    /// When `elf` is not an ELF, or its module imports a function the
    /// executor lacks.
    ///
    /// # Panics
    /// When the ELF loads but does not recompile (floating point, an
    /// unsupported relocation): guests are built for the recompiler.
    pub fn new(elf: &[u8], backend: Backend) -> Result<Runner, String> {
        let input = solo_recompile::Input::load(elf).map_err(|e| format!("guest ELF: {e:?}"))?;
        let module = solo_recompile::recompile(&input, &solo_recompile::Options::default())
            .expect("the guest recompiles");
        let mut exec = Executor::new(ModuleCache::default(), MemStorage::default());
        exec.set_backend(backend);
        let guest = exec
            .load(&module, Capability::Privileged)
            .map_err(|e| format!("guest module: {e:?}"))?;
        Ok(Runner {
            exec,
            guest,
            backend,
        })
    }

    /// The backend this runner uses.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// Whether the guest runs as native code: `None` before the first case
    /// under [`Backend::Native`].
    #[must_use]
    pub fn runs_natively(&self) -> Option<bool> {
        self.exec.runs_natively(&self.guest)
    }

    /// Runs `case` on empty storage.
    ///
    /// # Errors
    /// How the guest ended when it did not halt.
    ///
    /// # Panics
    /// If the guest halts with an output that is not an `Outcome`, or leaves
    /// storage that is not in the kernel's layout: both would be bugs in the
    /// guest, not results to compare.
    pub fn run(&mut self, case: &Case) -> Result<Executed, Termination> {
        *self.exec.state_mut() = Overlay::new(MemStorage::default());
        let result = self.exec.call_export(
            &self.guest,
            EXPORT,
            [0; 32],
            &case.to_bytes(),
            CASE_GAS,
            Capability::Privileged,
            Flags::default(),
        );
        if result.status != Termination::Halt {
            return Err(result.status);
        }
        let outcome = Outcome::from_bytes(&result.output).expect("the guest encodes an Outcome");
        Ok(Executed {
            outcome,
            post: self.post_state(),
        })
    }

    /// The accounts in storage, in the kernel's layout (`solo_abi::chain::keys`).
    fn post_state(&self) -> State {
        let storage = self.exec.state();
        let mut state = State::new();
        for (key, value) in storage.scan(keys::ACCOUNT) {
            let address: [u8; 20] = key[keys::ACCOUNT.len()..]
                .try_into()
                .expect("account keys end in an address");
            let stored = Stored::from_bytes(&value).expect("the kernel stores Accounts");
            let code = if stored.code_hash == [0; 32] {
                Vec::new()
            } else {
                storage
                    .get(&[keys::CODE, &stored.code_hash[..]].concat())
                    .expect("code is stored under its hash")
            };
            let prefix = [keys::SLOT, &address[..]].concat();
            let slots = storage
                .scan(&prefix)
                .into_iter()
                .map(|(k, v)| {
                    (
                        k[prefix.len()..]
                            .try_into()
                            .expect("slot keys end in a slot"),
                        v.try_into().expect("slot values are words"),
                    )
                })
                .collect();
            let mut balance = [0u8; 32];
            balance[16..].copy_from_slice(&stored.balance.to_be_bytes());
            state.insert(
                address,
                Account {
                    balance,
                    nonce: stored.nonce,
                    code,
                    storage: slots,
                },
            );
        }
        state
    }
}
