//! Kernel modules and native contracts (spec 16): the records the reference
//! kernel keeps for installed modules, the encoding of a module's input and
//! output, the native-contract designator, the namespace and gas rules, and
//! the governance `install` action.

use alloc::vec::Vec;

use crate::codec::{Decode, DecodeError, Decoder, Encode, Encoder, Seq};
use crate::types::{Address, Hash};

macro_rules! record {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $($(#[$fmeta])* pub $field: $ty,)*
        }
        impl Encode for $name {
            fn encode(&self, e: &mut Encoder) {
                $(self.$field.encode(e);)*
            }
        }
        impl Decode for $name {
            fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                Ok($name { $($field: d.get()?,)* })
            }
        }
    };
}

/// The two bytes that start the code of a native contract (spec 16 §5.1).
pub const DESIGNATOR_PREFIX: [u8; 2] = [0xEF, 0x02];

/// Length of a native-contract designator: the prefix and a code hash.
pub const DESIGNATOR_LEN: usize = 34;

/// The code of an account that dispatches to the module `code_hash`.
#[must_use]
pub fn designator(code_hash: &Hash) -> Vec<u8> {
    let mut code = Vec::with_capacity(DESIGNATOR_LEN);
    code.extend_from_slice(&DESIGNATOR_PREFIX);
    code.extend_from_slice(code_hash);
    code
}

/// The module code hash `code` designates, if it is a designator.
#[must_use]
pub fn designated(code: &[u8]) -> Option<Hash> {
    let hash = code.strip_prefix(&DESIGNATOR_PREFIX[..])?;
    hash.try_into().ok()
}

/// The storage namespace of the module or native contract at `address`: the
/// address left-padded with zeros to 32 bytes, as an ABI word holds it.
#[must_use]
pub fn namespace(address: &Address) -> Hash {
    let mut ns = [0u8; 32];
    ns[12..].copy_from_slice(address);
    ns
}

/// Largest module the kernel installs, in bytes: one storage value.
pub const MAX_MODULE_SIZE: usize = 65_536;

/// VM gas bought by one unit of EVM gas (spec 16 §6).
pub const VM_GAS_PER_EVM_GAS: u64 = 20;

/// EVM gas every call to a native contract costs before the module runs.
pub const CALL_GAS: u64 = 100;

/// EVM gas per entry of a native call's write set.
pub const WRITE_GAS: u64 = 5_000;

/// EVM gas per started 32-byte word of a written key and value.
pub const WRITE_WORD_GAS: u64 = 600;

/// VM gas each `init` and each block hook runs with.
pub const HOOK_GAS: u64 = 1 << 24;

/// Largest key of a module's storage, as the host allows (spec 05 §4.2).
pub const MAX_KEY_LEN: usize = 64;

/// Largest value of a module's storage, as the host allows (spec 05 §4.2).
pub const MAX_VALUE_LEN: usize = 65_536;

/// The EVM gas a native call costs for `vm_gas` used by its module: whole
/// units, rounded up.
#[must_use]
pub const fn evm_gas(vm_gas: u64) -> u64 {
    vm_gas.div_ceil(VM_GAS_PER_EVM_GAS)
}

/// The EVM gas a write set costs (spec 16 §6).
#[must_use]
pub fn write_gas(writes: &[Write]) -> u64 {
    writes.iter().fold(0u64, |total, w| {
        let bytes = w.key.len() + w.value.as_ref().map_or(0, Vec::len);
        total.saturating_add(WRITE_GAS + WRITE_WORD_GAS * bytes.div_ceil(32) as u64)
    })
}

/// Whether every entry of a write set has a key the host would accept and
/// a value it would store.
#[must_use]
pub fn writes_valid(writes: &[Write]) -> bool {
    writes.iter().all(|w| {
        (1..=MAX_KEY_LEN).contains(&w.key.len())
            && w.value.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_LEN)
    })
}

/// Kernel capability bits of an installed module (spec 16 §3).
pub mod capability {
    /// The kernel calls the module's `begin_block` and `end_block`.
    pub const HOOKS: u64 = 1;
    /// `init` and the block hooks run with the host's `Privileged` set and
    /// full keys. Granted only at genesis.
    pub const PRIVILEGED: u64 = 2;
    /// Every bit this kernel defines; any other bit makes an install fail.
    pub const KNOWN: u64 = HOOKS | PRIVILEGED;
}

/// Storage keys of the module registry.
pub mod keys {
    use alloc::vec::Vec;

    /// Prefix of a module record, followed by the 20-byte address.
    pub const MODULE: &[u8] = b"module/";
    /// The addresses of installed modules in ascending order.
    pub const MODULES: &[u8] = b"meta/modules";

    /// Key of the record of the module at `address`.
    #[must_use]
    pub fn module(address: &crate::types::Address) -> Vec<u8> {
        let mut k = Vec::with_capacity(MODULE.len() + 20);
        k.extend_from_slice(MODULE);
        k.extend_from_slice(address);
        k
    }
}

/// Query methods of the module registry.
pub mod query {
    /// `Address` → `ModuleRecord` of the module installed there.
    pub const MODULE: &str = "module";
    /// `ModuleQuery` → the module's `query` output.
    pub const MODULE_QUERY: &str = "module_query";
}

/// Status of a module's output.
pub mod status {
    /// The call succeeded: data is return data, writes are applied.
    pub const RETURN: u8 = 0;
    /// The call reverted: data is revert data, writes are discarded.
    pub const REVERT: u8 = 1;
}

/// The module system address that carries governance installs (spec 16 §4.2).
pub const MODULE_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x11,
];

record! {
    /// An installed module, at key `module/` ‖ address.
    ModuleRecord {
        /// The module's code hash; its bytes are at `code/` ‖ hash.
        code_hash: Hash,
        /// Capability bits.
        capabilities: u64,
        /// Height of the block that installed it; 0 at genesis.
        installed_at: u64,
    }
}

record! {
    /// One entry of a write set: a key of the module's namespace and its new
    /// value, or `None` to delete it.
    Write {
        /// Key, 1 to 64 bytes.
        key: Vec<u8>,
        /// Value of at most 65 536 bytes, or `None` to delete.
        value: Option<Vec<u8>>,
    }
}

record! {
    /// What a native contract learns about the call it serves.
    CallContext {
        /// The native contract's own address.
        address: Address,
        /// The caller (`msg.sender`).
        caller: Address,
        /// Wei transferred with the call (`msg.value`).
        value: u128,
        /// Height of the block.
        height: u64,
        /// Block timestamp in seconds.
        timestamp: u64,
        /// Whether the call is static: the write set must be empty.
        is_static: bool,
    }
}

record! {
    /// Argument of a `module_query`.
    ModuleQuery {
        /// The module's address.
        address: Address,
        /// Query data, passed through.
        data: Vec<u8>,
    }
}

record! {
    /// The output blob of a module (spec 16 §2.2).
    ModuleOutput {
        /// `status::RETURN` or `status::REVERT`.
        status: u8,
        /// Return or revert data.
        data: Vec<u8>,
        /// Storage writes, in order; a later entry for a key wins.
        writes: Seq<Write>,
    }
}

/// The input blob of a module's `main` (spec 16 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleCall {
    /// Once, when the module is installed.
    Init {
        /// The install's init argument.
        arg: Vec<u8>,
    },
    /// Before the first transaction of every block.
    BeginBlock {
        /// Height.
        height: u64,
        /// Timestamp in milliseconds.
        timestamp_ms: u64,
    },
    /// After the last transaction of every block.
    EndBlock {
        /// Height.
        height: u64,
        /// Timestamp in milliseconds.
        timestamp_ms: u64,
    },
    /// A message call from the EVM to a native contract running the module.
    Call {
        /// The call's context.
        context: CallContext,
        /// Calldata.
        data: Vec<u8>,
        /// Writes earlier native calls of this transaction made to this
        /// namespace and that still stand, oldest first.
        pending: Seq<Write>,
    },
    /// A read through the `module_query` query method.
    Query {
        /// Query data.
        data: Vec<u8>,
    },
}

impl Encode for ModuleCall {
    fn encode(&self, e: &mut Encoder) {
        match self {
            ModuleCall::Init { arg } => {
                e.raw(&[0]);
                e.put(arg);
            }
            ModuleCall::BeginBlock {
                height,
                timestamp_ms,
            } => {
                e.raw(&[1]);
                e.put(height).put(timestamp_ms);
            }
            ModuleCall::EndBlock {
                height,
                timestamp_ms,
            } => {
                e.raw(&[2]);
                e.put(height).put(timestamp_ms);
            }
            ModuleCall::Call {
                context,
                data,
                pending,
            } => {
                e.raw(&[3]);
                e.put(context).put(data).put(pending);
            }
            ModuleCall::Query { data } => {
                e.raw(&[4]);
                e.put(data);
            }
        }
    }
}

impl Decode for ModuleCall {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(match d.raw(1)?[0] {
            0 => ModuleCall::Init { arg: d.get()? },
            1 => ModuleCall::BeginBlock {
                height: d.get()?,
                timestamp_ms: d.get()?,
            },
            2 => ModuleCall::EndBlock {
                height: d.get()?,
                timestamp_ms: d.get()?,
            },
            3 => ModuleCall::Call {
                context: d.get()?,
                data: d.get()?,
                pending: d.get()?,
            },
            4 => ModuleCall::Query { data: d.get()? },
            t => return Err(DecodeError::BadTag(t)),
        })
    }
}

/// Selector of `install(address,bytes32,uint64,bytes)`.
pub const INSTALL_SELECTOR: [u8; 4] = [0xd3, 0x8e, 0xbb, 0xe9];

/// Topic 0 of `ModuleInstalled(address indexed target, bytes32 indexed codeHash, uint64 capabilities)`.
pub const INSTALLED_TOPIC: Hash = [
    0x30, 0x8a, 0x7d, 0xd0, 0xf9, 0x9c, 0x51, 0x51, 0xbb, 0xeb, 0x7b, 0x2d, 0x65, 0x86, 0xf8, 0x16,
    0x9b, 0xe5, 0x76, 0x90, 0x18, 0x00, 0x49, 0x00, 0xbe, 0x38, 0x54, 0xc7, 0x75, 0xee, 0x0e, 0x36,
];

/// Largest `init` argument a governance install carries.
pub const MAX_INIT_LEN: usize = 4_096;

/// A governance install (spec 16 §4.2): the calldata of a transaction to
/// [`MODULE_ADDRESS`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Install {
    /// The account that becomes the module's native contract.
    pub target: Address,
    /// The module's code hash; its code is staged under it (spec 13 §3).
    pub code_hash: Hash,
    /// Capability bits.
    pub capabilities: u64,
    /// The `init` argument.
    pub init: Vec<u8>,
}

fn word(value: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&value.to_be_bytes());
    w
}

/// The value of a 32-byte ABI word whose first `32 - 8` bytes are zero.
fn uint64(w: &[u8]) -> Option<u64> {
    let (high, low) = w.split_at(24);
    high.iter()
        .all(|b| *b == 0)
        .then(|| u64::from_be_bytes(low.try_into().expect("8 bytes")))
}

impl Install {
    /// The calldata of this install.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 * 6 + self.init.len());
        out.extend_from_slice(&INSTALL_SELECTOR);
        out.extend_from_slice(&namespace(&self.target));
        out.extend_from_slice(&self.code_hash);
        out.extend_from_slice(&word(self.capabilities));
        out.extend_from_slice(&word(128));
        out.extend_from_slice(&word(self.init.len() as u64));
        out.extend_from_slice(&self.init);
        out.resize(
            out.len() + self.init.len().next_multiple_of(32) - self.init.len(),
            0,
        );
        out
    }

    /// The install `data` encodes, if it is the canonical Solidity encoding
    /// of one with an `init` of at most [`MAX_INIT_LEN`] bytes.
    ///
    /// # Panics
    /// Never: every slice converted has the length it converts to.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Install> {
        let body = data.strip_prefix(&INSTALL_SELECTOR[..])?;
        if body.len() < 160 {
            return None;
        }
        let w = |i: usize| &body[32 * i..32 * i + 32];
        let target_word = w(0);
        let capabilities = uint64(w(2))?;
        if target_word[..12].iter().any(|b| *b != 0) || uint64(w(3))? != 128 {
            return None;
        }
        let len = usize::try_from(uint64(w(4))?)
            .ok()
            .filter(|n| *n <= MAX_INIT_LEN)?;
        let rest = &body[160..];
        let canonical =
            rest.len() == len.next_multiple_of(32) && rest[len..].iter().all(|b| *b == 0);
        canonical.then(|| Install {
            target: target_word[12..].try_into().expect("20 bytes"),
            code_hash: w(1).try_into().expect("32 bytes"),
            capabilities,
            init: rest[..len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    #[test]
    fn designators() {
        let code = designator(&[7; 32]);
        assert_eq!(code.len(), DESIGNATOR_LEN);
        assert_eq!(&code[..2], &[0xEF, 0x02]);
        assert_eq!(designated(&code), Some([7; 32]));
        assert_eq!(designated(&code[..33]), None);
        let mut long = code.clone();
        long.push(0);
        assert_eq!(designated(&long), None);
        assert_eq!(designated(&[0xEF, 0x01, 0x00]), None);
        assert_eq!(designated(b""), None);
    }

    #[test]
    fn namespaces_pad_the_address() {
        let ns = namespace(&[0xAB; 20]);
        assert_eq!(&ns[..12], &[0; 12]);
        assert_eq!(&ns[12..], &[0xAB; 20]);
        assert_eq!(keys::module(&[1; 20]).len(), 27);
        assert!(keys::module(&[1; 20]).starts_with(keys::MODULE));
    }

    /// The gas schedule of spec 16 §6, pinned.
    #[test]
    fn gas_schedule() {
        assert_eq!(VM_GAS_PER_EVM_GAS, 20);
        assert_eq!(CALL_GAS, 100);
        assert_eq!(WRITE_GAS, 5_000);
        assert_eq!(WRITE_WORD_GAS, 600);
        assert_eq!(HOOK_GAS, 16_777_216);
        assert_eq!(evm_gas(0), 0);
        assert_eq!(evm_gas(1), 1);
        assert_eq!(evm_gas(20), 1);
        assert_eq!(evm_gas(21), 2);
        let writes = [
            Write {
                key: vec![1; 5],
                value: Some(vec![2; 32]),
            },
            Write {
                key: vec![1; 32],
                value: None,
            },
        ];
        assert_eq!(write_gas(&writes), 5_000 + 2 * 600 + 5_000 + 600);
        assert_eq!(write_gas(&[]), 0);
    }

    #[test]
    fn write_sets_are_checked() {
        let ok = Write {
            key: vec![1],
            value: Some(vec![0; MAX_VALUE_LEN]),
        };
        assert!(writes_valid(core::slice::from_ref(&ok)));
        assert!(writes_valid(&[Write {
            key: vec![1; MAX_KEY_LEN],
            value: None
        }]));
        assert!(!writes_valid(&[Write {
            key: vec![],
            value: None
        }]));
        assert!(!writes_valid(&[Write {
            key: vec![1; MAX_KEY_LEN + 1],
            value: None
        }]));
        assert!(!writes_valid(&[
            ok,
            Write {
                key: vec![1],
                value: Some(vec![0; MAX_VALUE_LEN + 1])
            }
        ]));
    }

    #[test]
    fn records_roundtrip() {
        roundtrip(&ModuleRecord {
            code_hash: [3; 32],
            capabilities: capability::HOOKS,
            installed_at: 9,
        });
        roundtrip(&ModuleQuery {
            address: [4; 20],
            data: vec![1, 2],
        });
        roundtrip(&ModuleOutput {
            status: status::REVERT,
            data: vec![5],
            writes: Seq(vec![Write {
                key: vec![1],
                value: Some(vec![2]),
            }]),
        });
        let context = CallContext {
            address: [1; 20],
            caller: [2; 20],
            value: 3,
            height: 4,
            timestamp: 5,
            is_static: true,
        };
        for call in [
            ModuleCall::Init { arg: vec![1] },
            ModuleCall::BeginBlock {
                height: 1,
                timestamp_ms: 2,
            },
            ModuleCall::EndBlock {
                height: 3,
                timestamp_ms: 4,
            },
            ModuleCall::Call {
                context,
                data: vec![9],
                pending: Seq(vec![Write {
                    key: vec![1],
                    value: None,
                }]),
            },
            ModuleCall::Query { data: vec![8] },
        ] {
            roundtrip(&call);
        }
        assert_eq!(ModuleCall::from_bytes(&[5]), Err(DecodeError::BadTag(5)));
        assert_eq!(MODULE_ADDRESS[18..], [0x50, 0x11]);
        assert_eq!(capability::KNOWN, 3);
        assert_eq!(query::MODULE, "module");
        assert_eq!(query::MODULE_QUERY, "module_query");
        assert_eq!(status::RETURN, 0);
    }

    #[test]
    fn installs_roundtrip_canonically() {
        let install = Install {
            target: [9; 20],
            code_hash: [8; 32],
            capabilities: capability::HOOKS,
            init: vec![1, 2, 3],
        };
        let data = install.encode();
        assert_eq!(data.len(), 4 + 32 * 6);
        assert_eq!(Install::decode(&data), Some(install.clone()));
        let empty = Install {
            init: vec![],
            ..install.clone()
        };
        assert_eq!(Install::decode(&empty.encode()), Some(empty));
        let full = Install {
            init: vec![7; MAX_INIT_LEN],
            ..install.clone()
        };
        assert_eq!(Install::decode(&full.encode()), Some(full));
        let too_long = Install {
            init: vec![7; MAX_INIT_LEN + 1],
            ..install
        };
        assert_eq!(Install::decode(&too_long.encode()), None);

        let mutate = |at: usize, byte: u8| {
            let mut d = data.clone();
            d[at] = byte;
            Install::decode(&d)
        };
        assert_eq!(mutate(0, 0), None, "selector");
        assert_eq!(mutate(4, 1), None, "address word with high bytes");
        assert_eq!(mutate(4 + 64 + 3, 1), None, "capabilities above 64 bits");
        assert_eq!(mutate(4 + 96 + 31, 0x60), None, "offset");
        assert_eq!(mutate(4 + 96 + 3, 1), None, "offset above 64 bits");
        assert_eq!(mutate(4 + 128 + 3, 1), None, "length above 64 bits");
        assert_eq!(mutate(4 + 160 + 3, 1), None, "padding");
        assert_eq!(Install::decode(&data[..data.len() - 1]), None);
        assert_eq!(Install::decode(&data[..100]), None);
        let mut longer = data.clone();
        longer.extend_from_slice(&[0; 32]);
        assert_eq!(Install::decode(&longer), None);
    }
}
