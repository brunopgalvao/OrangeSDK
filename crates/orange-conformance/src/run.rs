//! Running a case: the conformance guest on the OrangeSDK VM, with the post-state
//! read back from the storage the kernel's state code wrote.

use orange_abi::chain::{Account as Stored, keys};
use orange_abi::conformance::{Case, EXPORT, EXPORT_GATED, Outcome};
use orange_abi::{Decode, Encode};
use orange_host::{Backend, Executor, Flags, MemStorage, ModuleCache, Overlay};
use orange_vm::host::Capability;
use orange_vm::status::Termination;

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
    /// are reached only through the account), but OrangeSDK's own commitment
    /// (spec 10) covers them and they would reappear under a new account at
    /// the address, so any is a failure of its own.
    pub orphans: Vec<[u8; 20]>,
}

/// The conformance guest loaded into an executor.
pub struct Runner {
    exec: Executor<MemStorage>,
    guest: [u8; 32],
    backend: Backend,
    gas_used: u64,
    export: &'static str,
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
        Runner::with_options(elf, backend, &orange_recompile::Options::default())
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
        options: &orange_recompile::Options,
    ) -> Result<Runner, String> {
        let input = orange_recompile::Input::load(elf).map_err(|e| format!("guest ELF: {e:?}"))?;
        let module = orange_recompile::recompile(&input, options).expect("the guest recompiles");
        let mut exec = Executor::new(ModuleCache::default(), MemStorage::default());
        exec.set_backend(backend);
        let guest = exec
            .load(&module, Capability::Privileged)
            .map_err(|e| format!("guest module: {e:?}"))?;
        Ok(Runner {
            exec,
            guest,
            backend,
            gas_used: 0,
            export: EXPORT,
        })
    }

    /// [`Runner::new`] with feature gate 2 active: the host serves the
    /// precompile functions (spec 05 §4.8) and the guest runs each case
    /// through them, as the kernel does once the gate is active (spec 19).
    ///
    /// # Errors
    /// As [`Runner::new`].
    ///
    /// # Panics
    /// As [`Runner::new`].
    pub fn gated(elf: &[u8], backend: Backend) -> Result<Runner, String> {
        let mut runner = Runner::new(elf, backend)?;
        runner
            .exec
            .set_extension(Box::new(orange_host::precompiles::Gate2));
        runner.export = EXPORT_GATED;
        Ok(runner)
    }

    /// Whether the runner runs cases with gate 2 active.
    #[must_use]
    pub fn is_gated(&self) -> bool {
        self.export == EXPORT_GATED
    }

    /// The runner in reports: its backend, and the gate when active.
    #[must_use]
    pub fn label(&self) -> String {
        let gate = if self.is_gated() { " with gate 2" } else { "" };
        format!("{:?} backend{gate}", self.backend)
    }

    /// The backend this runner uses.
    #[must_use]
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// VM gas the guest used in the last call, whatever its outcome: the
    /// kernel gas a case costs, which the precompile measurements of spec
    /// 19 compare with the EVM gas it charged.
    #[must_use]
    pub fn gas_used(&self) -> u64 {
        self.gas_used
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
        let output = self.call(self.export, &case.to_bytes(), storage)?;
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
        self.gas_used = result.gas_used;
        if result.status != Termination::Halt {
            return Err(result.status);
        }
        Ok(result.output)
    }

    /// The accounts in storage, in the kernel's layout (`orange_abi::chain::keys`),
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
