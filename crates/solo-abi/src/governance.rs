//! Two-track governance of the reference kernel (spec 13 §9): the genesis
//! parameters, the proposal records, the calls a transaction to the
//! governance address carries beside the upgrade actions of spec 13 §2, the
//! events, the storage keys and the queries. Shared by the kernel, the node,
//! the RPC and the `solo` command.
//!
//! The governance address is the upgrade address of spec 13 §2. Under the
//! *key* track the genesis governance key acts alone, at once; under the
//! *stake* track validators vote on proposals weighed by stake, a passed
//! proposal waits out a timelock during which a guardian may veto it, and
//! anyone then executes it.

use alloc::vec;
use alloc::vec::Vec;

use crate::chain::Log;
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

/// The governance address, `0x0000000000000000000000000000000000005010`:
/// the upgrade address of spec 13 §2, which also carries proposals, votes
/// and the guardian's calls.
pub const GOVERNANCE_ADDRESS: Address = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x10,
];

/// Governance modes (spec 13 §9.1).
pub mod mode {
    /// The genesis governance key acts alone and at once: the mode of
    /// development chains.
    pub const KEY: u8 = 0;
    /// Validators decide by stake-weighted vote; the key is the guardian.
    pub const STAKE: u8 = 1;
}

/// Most proposals open at once.
pub const MAX_OPEN_PROPOSALS: usize = 16;

/// Largest action a proposal carries, in bytes: room for a mainnet
/// light-client checkpoint (spec 18 §3.4) within one storage value.
pub const MAX_PROPOSAL_DATA: usize = 32_768;

/// Gas every governance call (`submit`, `vote`, `execute`, `veto`, `pause`)
/// costs on top of the plain call, paid at the transaction's gas price to
/// the zero address like every fee; the gas limit must cover it.
pub const GOVERNANCE_GAS: u64 = 50_000;

/// VM gas the kernel gives a governed call to a bridge module (spec 18 §5)
/// when a proposal, the key or the guardian executes it.
pub const ACTION_GAS: u64 = 1 << 26;

/// Function selectors of the governance calls: the first four bytes of
/// `keccak256` of each signature.
pub mod selector {
    /// `submit(address,bytes)`.
    pub const SUBMIT: [u8; 4] = [0x76, 0x84, 0x6e, 0xdd];
    /// `vote(uint64,bool)`.
    pub const VOTE: [u8; 4] = [0xc7, 0xf2, 0x15, 0x60];
    /// `execute(uint64)`.
    pub const EXECUTE: [u8; 4] = [0xb5, 0x90, 0xbe, 0x77];
    /// `veto(uint64)`.
    pub const VETO: [u8; 4] = [0xc8, 0x05, 0x06, 0x30];
    /// `pause(address)`.
    pub const PAUSE: [u8; 4] = [0x76, 0xa6, 0x7a, 0x51];
    /// `setGuardian(address)`.
    pub const SET_GUARDIAN: [u8; 4] = [0x8a, 0x0d, 0xac, 0x4a];
    /// `setMode(uint8)`.
    pub const SET_MODE: [u8; 4] = [0x21, 0x17, 0x5b, 0x4a];
    /// `setParams(uint64,uint64,uint64,uint256)`.
    pub const SET_PARAMS: [u8; 4] = [0x94, 0xbc, 0x43, 0xb4];
}

/// Event topics: `keccak256` of each event signature.
pub mod event {
    use crate::types::Hash;

    /// `ProposalSubmitted(uint64 indexed id, address indexed proposer, address indexed target, bytes data, uint64 votingEnd)`.
    pub const SUBMITTED: Hash = [
        0x48, 0x81, 0xfa, 0xd8, 0xcd, 0x00, 0x56, 0xf1, 0x35, 0xd5, 0xf5, 0x5a, 0x32, 0x9f, 0x3a,
        0x57, 0x20, 0xf6, 0x64, 0x38, 0x96, 0x4f, 0x54, 0x39, 0x9f, 0x0f, 0x76, 0x05, 0xf6, 0xb1,
        0xa7, 0x31,
    ];
    /// `Voted(uint64 indexed id, address indexed voter, bool support, uint64 weight)`.
    pub const VOTED: Hash = [
        0xa1, 0x9d, 0x42, 0x9d, 0x38, 0x88, 0xf3, 0x4f, 0x42, 0x07, 0x70, 0x91, 0xb3, 0x95, 0x45,
        0x4b, 0xca, 0x4a, 0xd4, 0x20, 0xce, 0x11, 0x31, 0x91, 0x62, 0xce, 0x18, 0xa8, 0x90, 0x52,
        0x1a, 0xeb,
    ];
    /// `ProposalExecuted(uint64 indexed id)`.
    pub const EXECUTED: Hash = [
        0x2b, 0x39, 0x62, 0x14, 0x0c, 0xfa, 0xd6, 0x97, 0xe0, 0x4b, 0x60, 0xd4, 0x7a, 0xf7, 0x71,
        0xde, 0x85, 0x68, 0xe6, 0xea, 0xd5, 0xf4, 0x2b, 0x88, 0x73, 0xc4, 0xa8, 0xd1, 0x2b, 0xd2,
        0xb3, 0xc7,
    ];
    /// `ProposalVetoed(uint64 indexed id)`.
    pub const VETOED: Hash = [
        0xf6, 0x8b, 0xad, 0x5c, 0x9f, 0x26, 0x38, 0xc4, 0xc3, 0x52, 0x49, 0x16, 0x47, 0xb9, 0xe0,
        0x89, 0xb2, 0x43, 0x40, 0xd0, 0xb6, 0x33, 0x3f, 0xd5, 0x5a, 0xf0, 0xd5, 0x92, 0x0a, 0xf3,
        0xc3, 0xdd,
    ];
    /// `Enacted(address indexed by, address indexed target, bytes data)`:
    /// an action the key or the guardian executed at once.
    pub const ENACTED: Hash = [
        0x69, 0x25, 0x8e, 0x06, 0x9a, 0x72, 0xfe, 0xdd, 0x24, 0xbc, 0x2c, 0x7a, 0xd9, 0x5d, 0x8b,
        0x66, 0x1d, 0x3a, 0xe9, 0xb5, 0x1b, 0xbd, 0x4f, 0x89, 0xdd, 0x0b, 0xe5, 0xa6, 0x8e, 0xc2,
        0xc1, 0x77,
    ];
    /// `GuardianSet(address guardian)`.
    pub const GUARDIAN_SET: Hash = [
        0xe6, 0xc0, 0x9f, 0xfe, 0x45, 0x72, 0xdc, 0x9c, 0xea, 0xa5, 0xdd, 0xde, 0x4a, 0xe4, 0x1b,
        0xef, 0xa6, 0x55, 0xd6, 0xfd, 0xfe, 0x80, 0x52, 0x07, 0x7a, 0xf0, 0x97, 0x0f, 0x70, 0x0e,
        0x94, 0x2e,
    ];
    /// `ModeSet(uint8 mode)`.
    pub const MODE_SET: Hash = [
        0x39, 0x99, 0xb8, 0xac, 0x9b, 0xe5, 0x7c, 0xf2, 0xfb, 0x4f, 0x25, 0x08, 0x73, 0x3b, 0xf8,
        0x03, 0x39, 0x4c, 0x77, 0xfb, 0xea, 0xe3, 0x20, 0x3c, 0xf5, 0x59, 0x30, 0x67, 0x12, 0x5e,
        0x7c, 0x9c,
    ];
    /// `ParamsSet(uint64 votingBlocks, uint64 timelockBlocks, uint64 quorumBps, uint256 deposit)`.
    pub const PARAMS_SET: Hash = [
        0xe2, 0xbb, 0x55, 0x2b, 0xca, 0x62, 0xbf, 0x3e, 0xb3, 0xbc, 0x44, 0x24, 0x8b, 0x74, 0xdb,
        0xb7, 0x90, 0x14, 0x3a, 0xc2, 0x23, 0x07, 0x6a, 0xdd, 0x4c, 0xc5, 0x5c, 0x38, 0xbe, 0x3c,
        0xba, 0x18,
    ];
}

/// Storage keys of governance (spec 13 §9.7).
pub mod keys {
    use alloc::vec::Vec;

    use crate::types::Hash;

    /// `gov/mode` → `u8`, once the mode left its genesis value.
    pub const MODE: &[u8] = b"gov/mode";
    /// `gov/guardian` → `Address`, once set.
    pub const GUARDIAN: &[u8] = b"gov/guardian";
    /// `gov/params` → `GovernanceParams`, once changed by `setParams`.
    pub const PARAMS: &[u8] = b"gov/params";
    /// `gov/next` → `u64`, the id of the next proposal (ids start at 1).
    pub const NEXT: &[u8] = b"gov/next";
    /// `gov/open` → `vec<OpenProposal>`, the open proposals in id order.
    pub const OPEN: &[u8] = b"gov/open";
    /// `gov/proposal/` + id (big-endian u64) → `Proposal`.
    pub const PROPOSAL: &[u8] = b"gov/proposal/";
    /// `gov/vote/` + id ‖ validator id → `bool`, the validator's vote.
    pub const VOTE: &[u8] = b"gov/vote/";
    /// `gov/voters/` + id → `vec<[32]>`, the validators that voted.
    pub const VOTERS: &[u8] = b"gov/voters/";

    fn keyed(prefix: &[u8], id: u64) -> Vec<u8> {
        let mut k = prefix.to_vec();
        k.extend_from_slice(&id.to_be_bytes());
        k
    }

    /// The key of proposal `id`.
    #[must_use]
    pub fn proposal(id: u64) -> Vec<u8> {
        keyed(PROPOSAL, id)
    }

    /// The key of `validator`'s vote on proposal `id`.
    #[must_use]
    pub fn vote(id: u64, validator: &Hash) -> Vec<u8> {
        let mut k = keyed(VOTE, id);
        k.extend_from_slice(validator);
        k
    }

    /// The key of the voters of proposal `id`.
    #[must_use]
    pub fn voters(id: u64) -> Vec<u8> {
        keyed(VOTERS, id)
    }
}

/// Query methods (spec 13 §9.8).
pub mod query {
    /// `() -> GovernanceStatus`.
    pub const GOVERNANCE: &str = "governance";
    /// `(u64 id) -> ProposalView` of an open proposal; status 1 if it is
    /// not open, 2 for malformed parameters.
    pub const PROPOSAL: &str = "governance_proposal";
}

/// A proposal's status while it is open.
pub mod status {
    /// Votes are being taken.
    pub const VOTING: u8 = 0;
    /// Passed; waiting out the timelock, then for `execute`.
    pub const PASSED: u8 = 1;
}

record! {
    /// Genesis parameters of governance (spec 13 §9.1), `GenesisParams::governance`.
    GovernanceParams {
        /// [`mode::KEY`] or [`mode::STAKE`].
        mode: u8,
        /// Blocks a proposal takes votes for; at least 1 under the stake track.
        voting_blocks: u64,
        /// Blocks between the end of voting and the first block that may
        /// execute a passed proposal: the guardian's veto window.
        timelock_blocks: u64,
        /// Least share of the validator set's stake, in basis points, that
        /// must vote for a proposal to count; at most 10 000.
        quorum_bps: u64,
        /// Wei a proposer that is not a validator locks with its proposal;
        /// zero lets only validators propose.
        deposit: u128,
    }
}

record! {
    /// An open proposal (spec 13 §9.3).
    Proposal {
        /// Its id; ids start at 1 and never repeat.
        id: u64,
        /// The account that submitted it.
        proposer: Address,
        /// Wei it locked; zero for a validator's proposal.
        deposit: u128,
        /// The system address the action is for.
        target: Address,
        /// The action: calldata to `target`.
        data: Vec<u8>,
        /// Height of the block that submitted it.
        submitted_at: u64,
        /// The last block that takes votes.
        voting_end: u64,
        /// The first block that may execute it, once passed; zero on the fast track.
        executable_at: u64,
        /// The last block that may execute it; a passed proposal still open
        /// after it has expired.
        expires_at: u64,
        /// Whether it is a safety action: no timelock, passed by a majority
        /// of all stake and executed in the vote that reaches it.
        fast_track: bool,
        /// [`status`].
        status: u8,
        /// Stake that voted yes, as tallied at the end of voting.
        yes: u64,
        /// Stake that voted no, as tallied at the end of voting.
        no: u64,
        /// Stake of the whole validator set at the tally.
        total: u64,
    }
}

record! {
    /// One entry of the open list: a proposal and the next height at which
    /// the end of a block has to look at it (its voting end, then its expiry).
    OpenProposal {
        /// The proposal's id.
        id: u64,
        /// The height.
        due: u64,
    }
}

record! {
    /// A validator's vote as the queries list it.
    Ballot {
        /// Validator id.
        validator: Hash,
        /// Yes or no.
        support: bool,
        /// Its weight in the current validator set.
        weight: u64,
    }
}

record! {
    /// An open proposal with its live tally over the current validator set.
    ProposalView {
        /// The record.
        proposal: Proposal,
        /// Stake voting yes now.
        yes: u64,
        /// Stake voting no now.
        no: u64,
        /// Stake of the current validator set.
        total: u64,
        /// Every vote, in validator-set order.
        votes: Seq<Ballot>,
    }
}

record! {
    /// What the `governance` query returns.
    GovernanceStatus {
        /// The current mode.
        mode: u8,
        /// The genesis governance key.
        key: Address,
        /// The guardian; zero for none.
        guardian: Address,
        /// The parameters in force.
        params: GovernanceParams,
        /// The id the next proposal gets.
        next_id: u64,
        /// The open proposals, in id order.
        proposals: Seq<ProposalView>,
    }
}

/// A call to the governance address beside the upgrade actions (spec 13 §9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// Proposes the action `data` to `target`; under the key track, executes it.
    Submit {
        /// The system address the action is for.
        target: Address,
        /// The action's calldata.
        data: Vec<u8>,
    },
    /// A validator's vote.
    Vote {
        /// The proposal.
        id: u64,
        /// Yes or no.
        support: bool,
    },
    /// Executes a passed proposal after its timelock.
    Execute {
        /// The proposal.
        id: u64,
    },
    /// The guardian withdraws an open proposal.
    Veto {
        /// The proposal.
        id: u64,
    },
    /// The guardian pauses `target` at once.
    Pause {
        /// The pausable system address.
        target: Address,
    },
    /// Names the guardian (an action).
    SetGuardian {
        /// The guardian; zero for none.
        guardian: Address,
    },
    /// Switches the mode (an action; only from key to stake).
    SetMode {
        /// [`mode`].
        mode: u8,
    },
    /// Changes the proposal rules (an action).
    SetParams {
        /// Blocks a proposal takes votes for.
        voting_blocks: u64,
        /// The timelock.
        timelock_blocks: u64,
        /// The quorum.
        quorum_bps: u64,
        /// The deposit.
        deposit: u128,
    },
}

/// A 32-byte big-endian ABI word holding `value`.
#[must_use]
pub fn word(value: u128) -> Hash {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&value.to_be_bytes());
    w
}

/// The word holding `address`.
#[must_use]
pub fn address_word(address: &Address) -> Hash {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(address);
    w
}

/// The value of an ABI word of an unsigned type `bytes` wide, if every
/// higher byte is zero, as a canonical encoding requires.
fn uint(w: &[u8], bytes: usize) -> Option<u128> {
    let (high, low) = w.split_at(32 - bytes);
    let mut be = [0u8; 16];
    be[16 - bytes..].copy_from_slice(low);
    high.iter()
        .all(|b| *b == 0)
        .then_some(u128::from_be_bytes(be))
}

fn u64_of(w: &[u8]) -> Option<u64> {
    uint(w, 8).and_then(|v| u64::try_from(v).ok())
}

fn address_of(w: &[u8]) -> Option<Address> {
    w[..12]
        .iter()
        .all(|b| *b == 0)
        .then(|| w[12..].try_into().expect("20 bytes"))
}

/// The tail encoding of `bytes`: its length word and the data padded to whole words.
fn bytes_tail(data: &[u8]) -> Vec<u8> {
    let mut out = word(data.len() as u128).to_vec();
    out.extend_from_slice(data);
    out.resize(32 + data.len().next_multiple_of(32), 0);
    out
}

impl Call {
    /// The calldata of this call: the Solidity ABI encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Call::Submit { target, data } => {
                out.extend_from_slice(&selector::SUBMIT);
                out.extend_from_slice(&address_word(target));
                out.extend_from_slice(&word(64));
                out.extend_from_slice(&bytes_tail(data));
            }
            Call::Vote { id, support } => {
                out.extend_from_slice(&selector::VOTE);
                out.extend_from_slice(&word(u128::from(*id)));
                out.extend_from_slice(&word(u128::from(*support)));
            }
            Call::Execute { id } => {
                out.extend_from_slice(&selector::EXECUTE);
                out.extend_from_slice(&word(u128::from(*id)));
            }
            Call::Veto { id } => {
                out.extend_from_slice(&selector::VETO);
                out.extend_from_slice(&word(u128::from(*id)));
            }
            Call::Pause { target } => {
                out.extend_from_slice(&selector::PAUSE);
                out.extend_from_slice(&address_word(target));
            }
            Call::SetGuardian { guardian } => {
                out.extend_from_slice(&selector::SET_GUARDIAN);
                out.extend_from_slice(&address_word(guardian));
            }
            Call::SetMode { mode } => {
                out.extend_from_slice(&selector::SET_MODE);
                out.extend_from_slice(&word(u128::from(*mode)));
            }
            Call::SetParams {
                voting_blocks,
                timelock_blocks,
                quorum_bps,
                deposit,
            } => {
                out.extend_from_slice(&selector::SET_PARAMS);
                out.extend_from_slice(&word(u128::from(*voting_blocks)));
                out.extend_from_slice(&word(u128::from(*timelock_blocks)));
                out.extend_from_slice(&word(u128::from(*quorum_bps)));
                out.extend_from_slice(&word(*deposit));
            }
        }
        out
    }

    /// The call `data` encodes, or `None` if it is not the canonical
    /// encoding of one: zero high bytes in every word, `submit`'s offset
    /// word 64 and its data at most [`MAX_PROPOSAL_DATA`] bytes, padded with
    /// zeros to a whole word, and nothing after the arguments.
    ///
    /// # Panics
    /// Never: every slice is taken after its length is checked.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Call> {
        let (sel, body) = data.split_at_checked(4)?;
        let w = |i: usize| &body[32 * i..32 * i + 32];
        match <[u8; 4]>::try_from(sel).ok()? {
            selector::SUBMIT if body.len() >= 96 => {
                let target = address_of(w(0))?;
                let len = usize::try_from(uint(w(2), 8)?)
                    .ok()
                    .filter(|n| *n <= MAX_PROPOSAL_DATA)?;
                let (data, padding) = body[96..].split_at_checked(len)?;
                let canonical = uint(w(1), 8) == Some(64)
                    && padding.len() == len.next_multiple_of(32) - len
                    && padding.iter().all(|b| *b == 0);
                canonical.then(|| Call::Submit {
                    target,
                    data: data.to_vec(),
                })
            }
            selector::VOTE if body.len() == 64 => {
                let support = match uint(w(1), 1)? {
                    0 => false,
                    1 => true,
                    _ => return None,
                };
                Some(Call::Vote {
                    id: u64_of(w(0))?,
                    support,
                })
            }
            selector::EXECUTE if body.len() == 32 => Some(Call::Execute { id: u64_of(w(0))? }),
            selector::VETO if body.len() == 32 => Some(Call::Veto { id: u64_of(w(0))? }),
            selector::PAUSE if body.len() == 32 => Some(Call::Pause {
                target: address_of(w(0))?,
            }),
            selector::SET_GUARDIAN if body.len() == 32 => Some(Call::SetGuardian {
                guardian: address_of(w(0))?,
            }),
            selector::SET_MODE if body.len() == 32 => Some(Call::SetMode {
                mode: u8::try_from(uint(w(0), 1)?).ok()?,
            }),
            selector::SET_PARAMS if body.len() == 128 => Some(Call::SetParams {
                voting_blocks: u64_of(w(0))?,
                timelock_blocks: u64_of(w(1))?,
                quorum_bps: u64_of(w(2))?,
                deposit: uint(w(3), 16)?,
            }),
            _ => None,
        }
    }
}

/// Whether `voted = yes + no` out of `total` stake meets a quorum of
/// `quorum_bps`; nothing meets it with no stake.
#[must_use]
pub fn quorum(yes: u64, no: u64, total: u64, quorum_bps: u64) -> bool {
    let voted = u128::from(yes) + u128::from(no);
    total != 0 && voted * 10_000 >= u128::from(total) * u128::from(quorum_bps)
}

/// Whether a proposal passes on the normal track: quorum, and more than two
/// thirds of the stake that voted said yes.
#[must_use]
pub fn passes(yes: u64, no: u64, total: u64, quorum_bps: u64) -> bool {
    quorum(yes, no, total, quorum_bps)
        && u128::from(yes) * 3 > (u128::from(yes) + u128::from(no)) * 2
}

/// Whether a fast-track proposal passes: more than half of all stake said yes.
#[must_use]
pub fn fast_passes(yes: u64, total: u64) -> bool {
    u128::from(yes) * 2 > u128::from(total)
}

fn log(topics: Vec<Hash>, data: Vec<u8>) -> Log {
    Log {
        address: GOVERNANCE_ADDRESS,
        topics: Seq(topics),
        data,
    }
}

/// The log `submit` emits for a new proposal.
#[must_use]
pub fn submitted_log(p: &Proposal) -> Log {
    let mut data = word(64).to_vec();
    data.extend_from_slice(&word(u128::from(p.voting_end)));
    data.extend_from_slice(&bytes_tail(&p.data));
    log(
        vec![
            event::SUBMITTED,
            word(u128::from(p.id)),
            address_word(&p.proposer),
            address_word(&p.target),
        ],
        data,
    )
}

/// The log `vote` emits.
#[must_use]
pub fn voted_log(id: u64, voter: &Address, support: bool, weight: u64) -> Log {
    let mut data = word(u128::from(support)).to_vec();
    data.extend_from_slice(&word(u128::from(weight)));
    log(
        vec![event::VOTED, word(u128::from(id)), address_word(voter)],
        data,
    )
}

/// The log an executed proposal emits, before its action's own.
#[must_use]
pub fn executed_log(id: u64) -> Log {
    log(vec![event::EXECUTED, word(u128::from(id))], Vec::new())
}

/// The log `veto` emits.
#[must_use]
pub fn vetoed_log(id: u64) -> Log {
    log(vec![event::VETOED, word(u128::from(id))], Vec::new())
}

/// The log of an action the key or the guardian executed at once, before
/// the action's own.
#[must_use]
pub fn enacted_log(by: &Address, target: &Address, data: &[u8]) -> Log {
    let mut body = word(32).to_vec();
    body.extend_from_slice(&bytes_tail(data));
    log(
        vec![event::ENACTED, address_word(by), address_word(target)],
        body,
    )
}

/// The log of `setGuardian`.
#[must_use]
pub fn guardian_log(guardian: &Address) -> Log {
    log(vec![event::GUARDIAN_SET], address_word(guardian).to_vec())
}

/// The log of `setMode`.
#[must_use]
pub fn mode_log(mode: u8) -> Log {
    log(vec![event::MODE_SET], word(u128::from(mode)).to_vec())
}

/// The log of `setParams`.
#[must_use]
pub fn params_log(p: &GovernanceParams) -> Log {
    let mut data = word(u128::from(p.voting_blocks)).to_vec();
    data.extend_from_slice(&word(u128::from(p.timelock_blocks)));
    data.extend_from_slice(&word(u128::from(p.quorum_bps)));
    data.extend_from_slice(&word(p.deposit));
    log(vec![event::PARAMS_SET], data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Encode + Decode + PartialEq + core::fmt::Debug>(v: &T) {
        assert_eq!(&T::from_bytes(&v.to_bytes()).unwrap(), v);
    }

    fn proposal() -> Proposal {
        Proposal {
            id: 7,
            proposer: [1; 20],
            deposit: 5,
            target: [2; 20],
            data: vec![3, 4, 5],
            submitted_at: 10,
            voting_end: 13,
            executable_at: 16,
            expires_at: 19,
            fast_track: false,
            status: status::PASSED,
            yes: 8,
            no: 1,
            total: 10,
        }
    }

    #[test]
    fn records_roundtrip() {
        let params = GovernanceParams {
            mode: mode::STAKE,
            voting_blocks: 3,
            timelock_blocks: 2,
            quorum_bps: 5_000,
            deposit: 1 << 70,
        };
        roundtrip(&params);
        roundtrip(&proposal());
        roundtrip(&OpenProposal { id: 1, due: 2 });
        let ballot = Ballot {
            validator: [9; 32],
            support: true,
            weight: 4,
        };
        roundtrip(&ballot);
        roundtrip(&GovernanceStatus {
            mode: mode::KEY,
            key: [1; 20],
            guardian: [2; 20],
            params,
            next_id: 8,
            proposals: Seq(vec![ProposalView {
                proposal: proposal(),
                yes: 1,
                no: 2,
                total: 3,
                votes: Seq(vec![ballot]),
            }]),
        });
        assert!(alloc::format!("{:?}", GovernanceStatus::default()).contains("GovernanceStatus"));
        assert_eq!(GOVERNANCE_ADDRESS[18..], [0x50, 0x10]);
        assert!(GOVERNANCE_ADDRESS[..18].iter().all(|b| *b == 0));
        assert_eq!((mode::KEY, mode::STAKE), (0, 1));
        assert_eq!((status::VOTING, status::PASSED), (0, 1));
        assert_eq!(
            (
                MAX_OPEN_PROPOSALS,
                MAX_PROPOSAL_DATA,
                GOVERNANCE_GAS,
                ACTION_GAS
            ),
            (16, 32_768, 50_000, 1 << 26)
        );
        assert_eq!(
            (query::GOVERNANCE, query::PROPOSAL),
            ("governance", "governance_proposal")
        );
        for key in [
            keys::MODE,
            keys::GUARDIAN,
            keys::PARAMS,
            keys::NEXT,
            keys::OPEN,
            keys::PROPOSAL,
            keys::VOTE,
            keys::VOTERS,
        ] {
            assert!(key.starts_with(b"gov/"));
        }
        let k = keys::proposal(0x0102);
        assert_eq!((k.len(), &k[13..]), (21, &[0, 0, 0, 0, 0, 0, 1, 2][..]));
        let k = keys::vote(1, &[7; 32]);
        assert_eq!((k.len(), &k[17..]), (49, &[7u8; 32][..]));
        assert!(k.len() <= 64);
        assert_eq!(keys::voters(1).len(), 19);
    }

    #[test]
    fn calls_encode_canonically() {
        let calls = [
            Call::Submit {
                target: [0x50; 20],
                data: vec![1, 2, 3, 4, 5],
            },
            Call::Submit {
                target: [0x50; 20],
                data: vec![],
            },
            Call::Submit {
                target: [0x50; 20],
                data: vec![7; 64],
            },
            Call::Submit {
                target: [0x50; 20],
                data: vec![7; MAX_PROPOSAL_DATA],
            },
            Call::Vote {
                id: 3,
                support: true,
            },
            Call::Vote {
                id: u64::MAX,
                support: false,
            },
            Call::Execute { id: 4 },
            Call::Veto { id: 5 },
            Call::Pause { target: [0x45; 20] },
            Call::SetGuardian { guardian: [0; 20] },
            Call::SetMode { mode: 1 },
            Call::SetParams {
                voting_blocks: 1,
                timelock_blocks: 2,
                quorum_bps: 3,
                deposit: u128::MAX,
            },
        ];
        for call in &calls {
            assert_eq!(
                Call::decode(&call.encode()).as_ref(),
                Some(call),
                "{call:?}"
            );
        }
        let submit = calls[0].encode();
        assert_eq!(submit.len(), 4 + 32 * 4);
        assert_eq!(&submit[..4], &selector::SUBMIT);
        assert_eq!(&submit[4 + 12..4 + 32], &[0x50; 20]);
        assert_eq!(submit[4 + 63], 64);
        assert_eq!(submit[4 + 95], 5);
        assert_eq!(&submit[4 + 96..4 + 101], &[1, 2, 3, 4, 5]);
        assert_eq!(calls[1].encode().len(), 4 + 96);
        assert_eq!(calls[3].encode().len(), 4 + 96 + MAX_PROPOSAL_DATA);
        let vote = calls[4].encode();
        assert_eq!(vote.len(), 68);
        assert_eq!((vote[4 + 31], vote[4 + 63]), (3, 1));
        assert_eq!(calls[6].encode().len(), 36);
        assert_eq!(calls[11].encode().len(), 4 + 128);
    }

    #[test]
    fn only_canonical_encodings_within_limits_decode() {
        let submit = Call::Submit {
            target: [0x50; 20],
            data: vec![1, 2, 3, 4, 5],
        }
        .encode();
        let patch = |at: usize, byte: u8| {
            let mut v = submit.clone();
            v[at] = byte;
            v
        };
        let mut bad = vec![
            Vec::new(),
            vec![0x76, 0x84, 0x6e],
            vec![0xde, 0xad, 0xbe, 0xef],
            submit[..4 + 64].to_vec(),
            submit[..submit.len() - 1].to_vec(),
            patch(4, 1),
            patch(4 + 63, 96),
            patch(4 + 32, 1),
            patch(4 + 64, 1),
            patch(4 + 95, 33),
            patch(4 + 95, 4),
            patch(submit.len() - 1, 1),
        ];
        let mut longer = submit.clone();
        longer.extend_from_slice(&[0; 32]);
        bad.push(longer);
        let mut huge = submit.clone();
        huge[4 + 64..4 + 96].copy_from_slice(&word(MAX_PROPOSAL_DATA as u128 + 1));
        bad.push(huge);
        let too_long = Call::Submit {
            target: [0x50; 20],
            data: vec![7; MAX_PROPOSAL_DATA + 1],
        }
        .encode();
        bad.push(too_long);
        let vote = Call::Vote {
            id: 3,
            support: true,
        }
        .encode();
        bad.push(vote[..67].to_vec());
        let mut two = vote.clone();
        two[4 + 63] = 2;
        bad.push(two);
        let mut wide = vote.clone();
        wide[4 + 62] = 1;
        bad.push(wide);
        let mut wide = vote.clone();
        wide[4] = 1;
        bad.push(wide);
        let execute = Call::Execute { id: 4 }.encode();
        let mut long = execute.clone();
        long.push(0);
        bad.push(long);
        let mut wide = execute.clone();
        wide[4 + 23] = 1;
        bad.push(wide);
        let mut veto = Call::Veto { id: 5 }.encode();
        veto[4] = 1;
        bad.push(veto);
        let mut pause = Call::Pause { target: [0x45; 20] }.encode();
        pause[4 + 11] = 1;
        bad.push(pause);
        let mut guardian = Call::SetGuardian { guardian: [1; 20] }.encode();
        guardian[4] = 1;
        bad.push(guardian);
        let mut mode = Call::SetMode { mode: 1 }.encode();
        mode[4 + 30] = 1;
        bad.push(mode);
        let params = Call::SetParams {
            voting_blocks: 1,
            timelock_blocks: 2,
            quorum_bps: 3,
            deposit: 4,
        }
        .encode();
        bad.push(params[..4 + 96].to_vec());
        for (at, byte) in [(4, 1), (4 + 32, 1), (4 + 64, 1), (4 + 96 + 15, 1)] {
            let mut v = params.clone();
            v[at] = byte;
            bad.push(v);
        }
        for (i, data) in bad.iter().enumerate() {
            assert_eq!(Call::decode(data), None, "case {i}");
        }
    }

    #[test]
    fn tallies() {
        assert!(quorum(5, 0, 10, 5_000));
        assert!(quorum(2, 3, 10, 5_000));
        assert!(!quorum(2, 2, 10, 5_000));
        assert!(!quorum(0, 0, 0, 0));
        assert!(quorum(0, 0, 1, 0));
        // More than two thirds of the stake that voted, within quorum.
        assert!(passes(7, 3, 10, 5_000));
        assert!(!passes(6, 3, 10, 5_000));
        assert!(passes(1, 0, 10, 1_000));
        assert!(!passes(1, 0, 10, 1_001));
        assert!(!passes(0, 0, 10, 0));
        assert!(passes(u64::MAX, 0, u64::MAX, 10_000));
        assert!(fast_passes(6, 10));
        assert!(!fast_passes(5, 10));
        assert!(!fast_passes(0, 0));
        assert!(fast_passes(u64::MAX, u64::MAX));
    }

    #[test]
    fn logs() {
        let p = proposal();
        let l = submitted_log(&p);
        assert_eq!(l.address, GOVERNANCE_ADDRESS);
        assert_eq!(
            l.topics.0,
            vec![
                event::SUBMITTED,
                word(7),
                address_word(&[1; 20]),
                address_word(&[2; 20])
            ]
        );
        assert_eq!(l.data.len(), 128);
        assert_eq!((l.data[31], l.data[63], l.data[95]), (64, 13, 3));
        assert_eq!(&l.data[96..99], &[3, 4, 5]);
        let l = voted_log(7, &[1; 20], true, 4);
        assert_eq!(
            l.topics.0,
            vec![event::VOTED, word(7), address_word(&[1; 20])]
        );
        assert_eq!(l.data, [word(1), word(4)].concat());
        assert_eq!(executed_log(7).topics.0, vec![event::EXECUTED, word(7)]);
        assert!(executed_log(7).data.is_empty());
        assert_eq!(vetoed_log(8).topics.0, vec![event::VETOED, word(8)]);
        let l = enacted_log(&[1; 20], &[2; 20], &[9; 40]);
        assert_eq!(
            l.topics.0,
            vec![
                event::ENACTED,
                address_word(&[1; 20]),
                address_word(&[2; 20])
            ]
        );
        assert_eq!(l.data.len(), 128);
        assert_eq!((l.data[31], l.data[63]), (32, 40));
        assert_eq!(guardian_log(&[3; 20]).data, address_word(&[3; 20]));
        assert_eq!(guardian_log(&[3; 20]).topics.0, vec![event::GUARDIAN_SET]);
        assert_eq!(mode_log(1).data, word(1));
        assert_eq!(mode_log(1).topics.0, vec![event::MODE_SET]);
        let l = params_log(&GovernanceParams {
            mode: 1,
            voting_blocks: 1,
            timelock_blocks: 2,
            quorum_bps: 3,
            deposit: 4,
        });
        assert_eq!(l.data, [word(1), word(2), word(3), word(4)].concat());
        assert_eq!(l.topics.0, vec![event::PARAMS_SET]);
    }
}
