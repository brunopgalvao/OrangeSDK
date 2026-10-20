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
    /// Addresses with storage slots but no account, in order. Ethereum has
    /// no such thing, and the state root cannot show it (an account's slots
    /// are reached only through the account), but Solo's own commitment
    /// (spec 10) covers them and they would reappear under a new account at
    /// the address, so any is a failure of its own.
    pub orphans: Vec<[u8; 20]>,
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
        Runner::with_options(elf, backend, &solo_recompile::Options::default())
    }

    /// [`Runner::new`] with recompiler options other than the defaults the
    /// node uses: a smaller `heap_max`, to measure what a case keeps live.
    ///
    /// # Errors
    /// As [`Runner::new`].
    ///
    /// # Panics
    /// As [`Runner::new`].
    pub fn with_options(
        elf: &[u8],
        backend: Backend,
        options: &solo_recompile::Options,
    ) -> Result<Runner, String> {
        let input = solo_recompile::Input::load(elf).map_err(|e| format!("guest ELF: {e:?}"))?;
        let module = solo_recompile::recompile(&input, options).expect("the guest recompiles");
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
        self.run_on(case, MemStorage::default())
    }

    /// Runs `case` on `storage` rather than empty storage: state written in
    /// the kernel's layout before genesis allocation, for cases whose
    /// pre-state is too large to pass as allocations (many accounts sharing
    /// one code), or that is not one genesis could create.
    ///
    /// # Errors
    /// As [`Runner::run`].
    ///
    /// # Panics
    /// As [`Runner::run`].
    pub fn run_on(&mut self, case: &Case, storage: MemStorage) -> Result<Executed, Termination> {
        let output = self.call(EXPORT, &case.to_bytes(), storage)?;
        let outcome = Outcome::from_bytes(&output).expect("the guest encodes an Outcome");
        let (post, orphans) = self.post_state();
        Ok(Executed {
            outcome,
            post,
            orphans,
        })
    }

    /// Calls `export` of the guest with `input` on `storage` and returns its
    /// output.
    ///
    /// # Errors
    /// How the guest ended when it did not halt.
    pub fn call(
        &mut self,
        export: &str,
        input: &[u8],
        storage: MemStorage,
    ) -> Result<Vec<u8>, Termination> {
        *self.exec.state_mut() = Overlay::new(storage);
        let result = self.exec.call_export(
            &self.guest,
            export,
            [0; 32],
            input,
            CASE_GAS,
            Capability::Privileged,
            Flags::default(),
        );
        if result.status != Termination::Halt {
            return Err(result.status);
        }
        Ok(result.output)
    }

    /// The accounts in storage, in the kernel's layout (`solo_abi::chain::keys`),
    /// and the addresses that have slots but no account.
    fn post_state(&self) -> (State, Vec<[u8; 20]>) {
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
        let mut orphans: Vec<[u8; 20]> = storage
            .scan(keys::SLOT)
            .into_iter()
            .map(|(key, _)| {
                key[keys::SLOT.len()..keys::SLOT.len() + 20]
                    .try_into()
                    .expect("slot keys start with an address")
            })
            .filter(|address| !state.contains_key(address))
            .collect();
        orphans.dedup();
        (state, orphans)
    }
}
