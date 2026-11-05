//! Two-track governance of the reference kernel (spec 13 §9): the genesis
//! parameters, the proposal records, the calls a transaction to the
//! governance address carries beside the upgrade actions of spec 13 §2, the
//! events, the storage keys and the queries. Shared by the kernel, the node,
//! the RPC and the `orange` command.
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
use crate::fees::FeeParams;
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

/// Most normal-track proposals open at once, governed calls included: the
/// rest of [`MAX_OPEN_PROPOSALS`] is left to the safety actions of the fast
/// track (spec 13 §9.3).
pub const MAX_OPEN_NORMAL: usize = 12;

/// Most open normal-track proposals of one proposer.
pub const MAX_PROPOSER_NORMAL: usize = 2;

/// Most open fast-track proposals of one proposer.
pub const MAX_PROPOSER_FAST: usize = 1;

/// Largest action a proposal carries, in bytes: room for a mainnet
/// light-client checkpoint (spec 18 §3.4) within one storage value.
pub const MAX_PROPOSAL_DATA: usize = 32_768;

/// Most delegators' votes of pruned proposals the end of a block deletes
/// (spec 13 §9.3): more than a block's governance calls can cast, so what
/// pruning leaves never piles up, and no number of votes on one proposal
/// makes a block's bookkeeping unbounded.
pub const SWEEP_BALLOTS: u32 = 1_024;

/// Most gas a governed call (`submitCall`, spec 13 §9.2) may carry.
pub const MAX_CALL_GAS: u64 = 10_000_000;

/// Most bytes of a governed call's return data its `CallExecuted` log keeps.
pub const MAX_CALL_OUTPUT: usize = 1_024;

/// Whether `address` is a system address: its first 18 bytes are zero, as
/// for the governance, module, staking and bridge addresses and the
/// precompiles. A governed call never targets one; the actions of spec 13
/// §9.2 reach them.
#[must_use]
pub fn is_system(address: &Address) -> bool {
    address[..18].iter().all(|b| *b == 0)
}

/// Gas every governance call (`submit`, `vote`, `execute`, `veto`, `pause`)
/// costs on top of the plain call, paid at the transaction's gas price to
/// the zero address like every fee; the gas limit must cover it.
pub const GOVERNANCE_GAS: u64 = 50_000;

/// VM gas the kernel gives a governed call to a bridge module (spec 18 §5)
/// when a proposal, the key or the guardian executes it.
pub const ACTION_GAS: u64 = 1 << 26;

/// The gas a message to `to` with calldata `data` pays beyond the plain
/// call: [`GOVERNANCE_GAS`] for a governance call, plus the gas of the call
/// a `submitCall` carries, nothing for anything else, upgrade actions
/// included. Admission requires a gas limit that covers it, and the
/// kernel's `call` query reports it, so that an `eth_estimateGas` is a gas
/// limit the chain accepts (spec 13 §9.9). The kernel adds the call's gas
/// to an `execute` of a call proposal, which this function cannot see.
#[must_use]
pub fn surcharge(to: Option<&Address>, data: &[u8]) -> u64 {
    match to {
        Some(to) if *to == GOVERNANCE_ADDRESS => match Call::decode(data) {
            Some(Call::SubmitCall { gas, .. }) => GOVERNANCE_GAS + gas,
            Some(_) => GOVERNANCE_GAS,
            None => 0,
        },
        _ => 0,
    }
}

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
    /// `setFeeParams(uint64,uint64,uint64,address)`.
    pub const SET_FEE_PARAMS: [u8; 4] = [0x92, 0x10, 0x6b, 0x6c];
    /// `submitCall(address,uint256,uint64,bytes)`.
    pub const SUBMIT_CALL: [u8; 4] = [0x0d, 0xfe, 0x20, 0x64];
    /// `reject(uint64)`.
    pub const REJECT: [u8; 4] = [0x50, 0x44, 0xa7, 0x60];
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
    /// `FeeParamsSet(uint64 denominator, uint64 elasticity, uint64 minBaseFee, address treasury)`
    /// (spec 23 §5).
    pub const FEE_PARAMS_SET: Hash = [
        0xcc, 0x7e, 0x28, 0xc1, 0x18, 0xac, 0xfb, 0x02, 0xd3, 0x64, 0x8a, 0xe5, 0xd9, 0x95, 0xa8,
        0x16, 0x6f, 0x73, 0x41, 0x3d, 0xfa, 0x1e, 0x90, 0xdb, 0xee, 0x1a, 0x24, 0xff, 0x2e, 0xfe,
        0xb4, 0xd8,
    ];
    /// `CallExecuted(uint64 indexed id, address indexed target, bool success, uint64 gasUsed, bytes output)`.
    pub const CALL_EXECUTED: Hash = [
        0xe0, 0x3e, 0xc1, 0x32, 0x00, 0x48, 0x97, 0x3d, 0x79, 0xe1, 0x12, 0x8f, 0x8b, 0xe1, 0x49,
        0x00, 0x18, 0xbc, 0xca, 0xd3, 0x9d, 0xe5, 0x96, 0x72, 0x91, 0xa0, 0xb7, 0xd1, 0x68, 0x42,
        0xde, 0x45,
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
    /// `gov/ballot/` + id ‖ address → `u32`, the position of a delegator's
    /// vote under `gov/ballot_at/`.
    pub const BALLOT: &[u8] = b"gov/ballot/";
    /// `gov/ballots/` + id → `u32`, how many delegators voted.
    pub const BALLOTS: &[u8] = b"gov/ballots/";
    /// `gov/ballot_at/` + id ‖ index (big-endian u32) → `BallotEntry`, the
    /// delegators' votes, in the order they first voted.
    pub const BALLOT_AT: &[u8] = b"gov/ballot_at/";
    /// `gov/moved/` + id ‖ validator id → `Moved`, the running sums of the
    /// stake that delegators who voted hold behind the validator.
    pub const MOVED: &[u8] = b"gov/moved/";
    /// `gov/sweep` → `vec<Sweep>`, the votes of pruned proposals still to delete.
    pub const SWEEP: &[u8] = b"gov/sweep";
    /// `gov/executed/` + id → `Execution`, where an executed proposal ran.
    pub const EXECUTED: &[u8] = b"gov/executed/";

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

    /// The key of `delegator`'s vote on proposal `id`.
    #[must_use]
    pub fn ballot(id: u64, delegator: &crate::types::Address) -> Vec<u8> {
        let mut k = keyed(BALLOT, id);
        k.extend_from_slice(delegator);
        k
    }

    /// The key of the number of delegators that voted on proposal `id`.
    #[must_use]
    pub fn ballots(id: u64) -> Vec<u8> {
        keyed(BALLOTS, id)
    }

    /// The key of the `index`th delegator to vote on proposal `id`.
    #[must_use]
    pub fn ballot_at(id: u64, index: u32) -> Vec<u8> {
        let mut k = keyed(BALLOT_AT, id);
        k.extend_from_slice(&index.to_be_bytes());
        k
    }

    /// The key of the running sums of proposal `id` behind `validator`.
    #[must_use]
    pub fn moved(id: u64, validator: &Hash) -> Vec<u8> {
        let mut k = keyed(MOVED, id);
        k.extend_from_slice(validator);
        k
    }

    /// The key of where proposal `id` was executed.
    #[must_use]
    pub fn executed(id: u64) -> Vec<u8> {
        keyed(EXECUTED, id)
    }
}

/// Query methods (spec 13 §9.8).
pub mod query {
    /// `() -> GovernanceStatus`.
    pub const GOVERNANCE: &str = "governance";
    /// `(u64 id) -> ProposalView` of an open proposal; status 1 if it is
    /// not open, 2 for malformed parameters.
    pub const PROPOSAL: &str = "governance_proposal";
    /// `(u64 id) -> Execution` of an executed proposal; status 1 if it was
    /// not executed (or is still open), 2 for malformed parameters.
    pub const EXECUTED: &str = "governance_executed";
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

/// An open proposal (spec 13 §9.3).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Proposal {
    /// Its id; ids start at 1 and never repeat.
    pub id: u64,
    /// The account that submitted it.
    pub proposer: Address,
    /// Wei it locked; zero for a validator's proposal.
    pub deposit: u128,
    /// The system address the action is for, or, for a governed call, the
    /// account called.
    pub target: Address,
    /// The action, or the governed call's calldata.
    pub data: Vec<u8>,
    /// Height of the block that submitted it.
    pub submitted_at: u64,
    /// The last block that takes votes.
    pub voting_end: u64,
    /// The first block that may execute it, once passed; zero on the fast track.
    pub executable_at: u64,
    /// The last block that may execute it; a passed proposal still open
    /// after it has expired.
    pub expires_at: u64,
    /// Whether it is a safety action: no timelock, passed by a majority of
    /// all stake at the end of a block in which it took a vote.
    pub fast_track: bool,
    /// [`status`].
    pub status: u8,
    /// Stake that voted yes, as tallied at the end of voting.
    pub yes: u64,
    /// Stake that voted no, as tallied at the end of voting.
    pub no: u64,
    /// Stake of the whole validator set at the tally.
    pub total: u64,
    /// For a governed call, the wei the governance address sends with it.
    pub value: u128,
    /// For a governed call, its gas limit; zero for an action.
    pub gas: u64,
}

impl Proposal {
    /// Whether it carries a governed call rather than an action: its target
    /// is not a system address.
    #[must_use]
    pub fn is_call(&self) -> bool {
        !is_system(&self.target)
    }
}

impl Encode for Proposal {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.id)
            .put(&self.proposer)
            .put(&self.deposit)
            .put(&self.target)
            .put(&self.data)
            .put(&self.submitted_at)
            .put(&self.voting_end)
            .put(&self.executable_at)
            .put(&self.expires_at)
            .put(&self.fast_track)
            .put(&self.status)
            .put(&self.yes)
            .put(&self.no)
            .put(&self.total)
            .put(&self.value)
            .put(&self.gas);
    }
}

impl Decode for Proposal {
    /// A record a kernel before governed calls stored ends after `total`;
    /// it reads as an action, with no value and no gas.
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let mut p = Proposal {
            id: d.get()?,
            proposer: d.get()?,
            deposit: d.get()?,
            target: d.get()?,
            data: d.get()?,
            submitted_at: d.get()?,
            voting_end: d.get()?,
            executable_at: d.get()?,
            expires_at: d.get()?,
            fast_track: d.get()?,
            status: d.get()?,
            yes: d.get()?,
            no: d.get()?,
            total: d.get()?,
            value: 0,
            gas: 0,
        };
        if d.remaining() != 0 {
            p.value = d.get()?;
            p.gas = d.get()?;
        }
        Ok(p)
    }
}

record! {
    /// One entry of the open list: a proposal, the next height at which
    /// the end of a block has to look at it (its voting end, then its
    /// expiry), and its proposer and track, which the bounds of spec 13
    /// §9.3 count.
    OpenProposal {
        /// The proposal's id.
        id: u64,
        /// The height.
        due: u64,
        /// Who proposed it.
        proposer: Address,
        /// Whether it is on the fast track.
        fast_track: bool,
    }
}

record! {
    /// A validator's vote as the queries list it.
    Ballot {
        /// Validator id.
        validator: Hash,
        /// Yes or no.
        support: bool,
        /// The stake it carries now: its own and that of every delegation
        /// behind it whose delegator did not vote (spec 13 §9.3).
        weight: u64,
    }
}

record! {
    /// A delegator's vote as state keeps it (spec 13 §9.7).
    BallotEntry {
        /// The delegator.
        delegator: Address,
        /// Yes or no.
        support: bool,
    }
}

record! {
    /// What the delegators who voted on a proposal hold behind one
    /// validator (spec 13 §9.3): the sums, in gwei, of the bonded stake of
    /// their delegations to it, by the side they voted for. Kept up to date
    /// by every vote and every change of a delegation, so that a tally reads
    /// one of these per member instead of every delegator's vote.
    Moved {
        /// Behind the validator, voting yes.
        yes: u128,
        /// Behind the validator, voting no.
        no: u128,
    }
}

impl Moved {
    /// Replaces `old` gwei with `new` on the side `support` names: a
    /// delegation of a delegator who voted that way changed, or the vote
    /// came in (`old` 0) or moved to the other side (`new` 0).
    pub fn shift(&mut self, support: bool, old: u64, new: u64) {
        let side = if support { &mut self.yes } else { &mut self.no };
        *side = side.saturating_sub(u128::from(old)) + u128::from(new);
    }
}

record! {
    /// Votes of a pruned proposal still to delete: indices `next` up to
    /// `end` under `gov/ballot_at/` (spec 13 §9.3).
    Sweep {
        /// The proposal.
        id: u64,
        /// The next index to delete.
        next: u32,
        /// One past the last index.
        end: u32,
    }
}

record! {
    /// Where a proposal was executed (spec 13 §9.7): the block, and whether
    /// at its end, the logs then being in the block's system receipt (spec
    /// 20 §3.5), or by an `execute` transaction of the block, whose receipt
    /// carries them.
    Execution {
        /// The block's height.
        height: u64,
        /// Executed at the end of the block, not by a transaction.
        system: bool,
    }
}

record! {
    /// A delegator's vote as the queries list it.
    DelegatorBallot {
        /// The delegator.
        delegator: Address,
        /// Yes or no.
        support: bool,
        /// The bonded stake of its delegations behind members of the
        /// current set that count, in gwei, now.
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
        /// Every vote of a validator that counts, in validator-set order.
        votes: Seq<Ballot>,
        /// Every delegator's vote, in the order they first voted.
        delegators: Seq<DelegatorBallot>,
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
    /// Proposes a governed call: the governance address calls `target`
    /// with `value` and `data` and at most `gas`; under the key track,
    /// executes it at once.
    SubmitCall {
        /// The account called; never a system address.
        target: Address,
        /// Wei the governance address sends.
        value: u128,
        /// The call's gas limit, intrinsic gas included.
        gas: u64,
        /// The calldata.
        data: Vec<u8>,
    },
    /// Withdraws open proposal `id` (an action, on the fast track).
    Reject {
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
    /// Changes the fee market's parameters (an action, spec 23 §5).
    SetFeeParams {
        /// The new parameters.
        params: FeeParams,
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

/// The `bytes` argument whose offset word is word `head` of `body`, the
/// last argument: its offset must point right after the head, its length be
/// at most [`MAX_PROPOSAL_DATA`], its padding zeros to a whole word, and
/// nothing follow it. `body` holds at least `head + 2` words.
fn bytes_at(body: &[u8], head: usize) -> Option<Vec<u8>> {
    let offset = 32 * (head + 1);
    let len = usize::try_from(uint(&body[offset..offset + 32], 8)?)
        .ok()
        .filter(|n| *n <= MAX_PROPOSAL_DATA)?;
    let (data, padding) = body[offset + 32..].split_at_checked(len)?;
    let canonical = uint(&body[32 * head..32 * head + 32], 8) == Some(offset as u128)
        && padding.len() == len.next_multiple_of(32) - len
        && padding.iter().all(|b| *b == 0);
    canonical.then(|| data.to_vec())
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
            Call::SubmitCall {
                target,
                value,
                gas,
                data,
            } => {
                out.extend_from_slice(&selector::SUBMIT_CALL);
                out.extend_from_slice(&address_word(target));
                out.extend_from_slice(&word(*value));
                out.extend_from_slice(&word(u128::from(*gas)));
                out.extend_from_slice(&word(128));
                out.extend_from_slice(&bytes_tail(data));
            }
            Call::Reject { id } => {
                out.extend_from_slice(&selector::REJECT);
                out.extend_from_slice(&word(u128::from(*id)));
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
            Call::SetFeeParams { params } => {
                out.extend_from_slice(&selector::SET_FEE_PARAMS);
                out.extend_from_slice(&word(u128::from(params.denominator)));
                out.extend_from_slice(&word(u128::from(params.elasticity)));
                out.extend_from_slice(&word(u128::from(params.min_base_fee)));
                out.extend_from_slice(&address_word(&params.treasury));
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
                let data = bytes_at(body, 1)?;
                Some(Call::Submit { target, data })
            }
            selector::SUBMIT_CALL if body.len() >= 160 => {
                let target = address_of(w(0))?;
                let value = uint(w(1), 16)?;
                let gas = u64_of(w(2))?;
                let data = bytes_at(body, 3)?;
                Some(Call::SubmitCall {
                    target,
                    value,
                    gas,
                    data,
                })
            }
            selector::REJECT if body.len() == 32 => Some(Call::Reject { id: u64_of(w(0))? }),
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
            selector::SET_FEE_PARAMS if body.len() == 128 => Some(Call::SetFeeParams {
                params: FeeParams {
                    denominator: u64_of(w(0))?,
                    elasticity: u64_of(w(1))?,
                    min_base_fee: u64_of(w(2))?,
                    treasury: address_of(w(3))?,
                },
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

/// A member of the current validator set whose stake counts, for [`tally`]
/// (spec 13 §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Its weight: its own and its delegators' bonded stake, in gwei.
    pub weight: u64,
    /// Its validator's vote, if any.
    pub vote: Option<bool>,
}

/// A delegator's vote for [`tally`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegator {
    /// Yes or no.
    pub support: bool,
    /// Its bonded stake behind each member, in gwei, by the member's
    /// position: part of that member's weight.
    pub behind: Vec<(usize, u64)>,
}

/// What a [`tally`] gives.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tally {
    /// Stake voting yes.
    pub yes: u64,
    /// Stake voting no.
    pub no: u64,
    /// The members' whole stake.
    pub total: u64,
    /// Each member's weight less what its voting delegators took with them:
    /// what its validator's vote carries.
    pub effective: Vec<u64>,
    /// Each delegator's weight, in order.
    pub delegators: Vec<u64>,
}

/// The stake-weighted tally of spec 13 §9.3: a delegator's vote carries its
/// delegations, and takes them out of the weight its validators' votes
/// carry; a validator's vote carries the rest of its member's weight, its
/// own stake and every delegation whose delegator did not vote. Sums
/// saturate at `2^64 − 1` gwei.
///
/// # Panics
/// If a delegator names a member position out of range.
#[must_use]
pub fn tally(members: &[Member], delegators: &[Delegator]) -> Tally {
    let mut moved = vec![0u64; members.len()];
    let (mut yes, mut no) = (0u64, 0u64);
    let mut weights = Vec::with_capacity(delegators.len());
    for d in delegators {
        let mut weight = 0u64;
        for &(m, w) in &d.behind {
            moved[m] = moved[m].saturating_add(w);
            weight = weight.saturating_add(w);
        }
        if d.support {
            yes = yes.saturating_add(weight);
        } else {
            no = no.saturating_add(weight);
        }
        weights.push(weight);
    }
    let mut total = 0u64;
    let mut effective = Vec::with_capacity(members.len());
    for (m, taken) in members.iter().zip(moved) {
        total = total.saturating_add(m.weight);
        let w = m.weight.saturating_sub(taken);
        match m.vote {
            Some(true) => yes = yes.saturating_add(w),
            Some(false) => no = no.saturating_add(w),
            None => {}
        }
        effective.push(w);
    }
    Tally {
        yes,
        no,
        total,
        effective,
        delegators: weights,
    }
}

/// The tally of spec 13 §9.3 from running sums: each member that counts
/// with its validator's vote and what the delegators who voted hold behind
/// it ([`Moved`]). It gives the `yes`, `no` and `total` of [`tally`] over
/// the same votes, where each [`Delegator::behind`] lists the delegator's
/// stake behind the members, in time linear in the members alone.
#[must_use]
pub fn running_tally(members: &[(Member, Moved)]) -> (u64, u64, u64) {
    let cap = |x: u128| u64::try_from(x).unwrap_or(u64::MAX);
    let (mut yes, mut no, mut total) = (0u128, 0u128, 0u128);
    for (m, moved) in members {
        let weight = u128::from(m.weight);
        total += weight;
        yes = yes.saturating_add(moved.yes);
        no = no.saturating_add(moved.no);
        let rest = weight.saturating_sub(moved.yes.saturating_add(moved.no));
        match m.vote {
            Some(true) => yes = yes.saturating_add(rest),
            Some(false) => no = no.saturating_add(rest),
            None => {}
        }
    }
    (cap(yes), cap(no), cap(total))
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

/// The log of a governed call's execution (spec 13 §9.5): `id` 0 for one
/// the key executed at once; at most [`MAX_CALL_OUTPUT`] bytes of output.
#[must_use]
pub fn call_executed_log(
    id: u64,
    target: &Address,
    success: bool,
    gas_used: u64,
    output: &[u8],
) -> Log {
    let output = &output[..output.len().min(MAX_CALL_OUTPUT)];
    let mut data = word(u128::from(success)).to_vec();
    data.extend_from_slice(&word(u128::from(gas_used)));
    data.extend_from_slice(&word(96));
    data.extend_from_slice(&bytes_tail(output));
    log(
        vec![
            event::CALL_EXECUTED,
            word(u128::from(id)),
            address_word(target),
        ],
        data,
    )
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

/// The log of `setFeeParams` (spec 23 §5).
#[must_use]
pub fn fee_params_log(p: &FeeParams) -> Log {
    let mut data = word(u128::from(p.denominator)).to_vec();
    data.extend_from_slice(&word(u128::from(p.elasticity)));
    data.extend_from_slice(&word(u128::from(p.min_base_fee)));
    data.extend_from_slice(&address_word(&p.treasury));
    log(vec![event::FEE_PARAMS_SET], data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
            value: 11,
            gas: 12,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
        roundtrip(&OpenProposal {
            id: 1,
            due: 2,
            proposer: [3; 20],
            fast_track: true,
        });
        let ballot = Ballot {
            validator: [9; 32],
            support: true,
            weight: 4,
        };
        roundtrip(&ballot);
        roundtrip(&BallotEntry {
            delegator: [4; 20],
            support: true,
        });
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
                delegators: Seq(vec![DelegatorBallot {
                    delegator: [3; 20],
                    support: false,
                    weight: 5,
                }]),
            }]),
        });
        assert!(alloc::format!("{:?}", GovernanceStatus::default()).contains("GovernanceStatus"));
        // A record from a kernel before governed calls reads as an action.
        let mut legacy = proposal();
        let full = legacy.to_bytes();
        let old = &full[..full.len() - 24];
        (legacy.value, legacy.gas) = (0, 0);
        assert_eq!(Proposal::from_bytes(old), Ok(legacy.clone()));
        assert!(Proposal::from_bytes(&full[..full.len() - 1]).is_err());
        legacy.target = GOVERNANCE_ADDRESS;
        assert!(!legacy.is_call());
        legacy.target[0] = 1;
        assert!(legacy.is_call());
        assert!(is_system(&GOVERNANCE_ADDRESS) && is_system(&[0; 20]));
        let mut near = [0u8; 20];
        near[1] = 1;
        assert!(!is_system(&near));
        assert_eq!(
            (SWEEP_BALLOTS, MAX_CALL_GAS, MAX_CALL_OUTPUT),
            (1_024, 10_000_000, 1_024)
        );
        roundtrip(&Moved { yes: 1, no: 2 });
        roundtrip(&Sweep {
            id: 1,
            next: 2,
            end: 3,
        });
        roundtrip(&Execution {
            height: 4,
            system: true,
        });
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
            (query::GOVERNANCE, query::PROPOSAL, query::EXECUTED),
            ("governance", "governance_proposal", "governance_executed")
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
            keys::BALLOT,
            keys::BALLOTS,
            keys::BALLOT_AT,
            keys::MOVED,
            keys::SWEEP,
            keys::EXECUTED,
        ] {
            assert!(key.starts_with(b"gov/"));
        }
        let k = keys::proposal(0x0102);
        assert_eq!((k.len(), &k[13..]), (21, &[0, 0, 0, 0, 0, 0, 1, 2][..]));
        let k = keys::vote(1, &[7; 32]);
        assert_eq!((k.len(), &k[17..]), (49, &[7u8; 32][..]));
        assert!(k.len() <= 64);
        assert_eq!(keys::voters(1).len(), 19);
        let k = keys::ballot(1, &[7; 20]);
        assert_eq!((k.len(), &k[19..]), (39, &[7u8; 20][..]));
        assert_eq!(keys::ballots(1).len(), 20);
        let k = keys::ballot_at(1, 0x0102);
        assert_eq!((k.len(), &k[22..]), (26, &[0, 0, 1, 2][..]));
        let k = keys::moved(1, &[7; 32]);
        assert_eq!((k.len(), &k[18..]), (50, &[7u8; 32][..]));
        assert_eq!(keys::executed(1).len(), 21);
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
            Call::SubmitCall {
                target: [0x51; 20],
                value: u128::MAX,
                gas: 21_000,
                data: vec![1, 2, 3],
            },
            Call::SubmitCall {
                target: [0x51; 20],
                value: 0,
                gas: u64::MAX,
                data: vec![],
            },
            Call::Reject { id: 9 },
            Call::SetMode { mode: 1 },
            Call::SetParams {
                voting_blocks: 1,
                timelock_blocks: 2,
                quorum_bps: 3,
                deposit: u128::MAX,
            },
            Call::SetFeeParams {
                params: FeeParams {
                    denominator: 125,
                    elasticity: 2,
                    min_base_fee: u64::MAX,
                    treasury: [0x7; 20],
                },
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
        let submit_call = calls[10].encode();
        assert_eq!(submit_call.len(), 4 + 32 * 6);
        assert_eq!(&submit_call[..4], &selector::SUBMIT_CALL);
        assert_eq!(&submit_call[4 + 12..4 + 32], &[0x51; 20]);
        assert_eq!(&submit_call[4 + 48..4 + 64], &[0xFF; 16]);
        assert_eq!((submit_call[4 + 94], submit_call[4 + 95]), (0x52, 0x08));
        assert_eq!((submit_call[4 + 127], submit_call[4 + 159]), (128, 3));
        assert_eq!(calls[11].encode().len(), 4 + 32 * 5);
        assert_eq!(calls[12].encode().len(), 36);
        assert_eq!(&calls[12].encode()[..4], &selector::REJECT);
        assert_eq!(calls[14].encode().len(), 4 + 128);
        let fees = calls[15].encode();
        assert_eq!(fees.len(), 4 + 128);
        assert_eq!(&fees[..4], &selector::SET_FEE_PARAMS);
        assert_eq!((fees[4 + 31], fees[4 + 63], fees[4 + 108]), (125, 2, 7));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
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
        let fees = Call::SetFeeParams {
            params: FeeParams::production(),
        }
        .encode();
        bad.push(fees[..4 + 96].to_vec());
        for (at, byte) in [
            (4 + 23, 1),
            (4 + 32 + 23, 1),
            (4 + 64 + 23, 1),
            (4 + 96 + 11, 1),
        ] {
            let mut v = fees.clone();
            v[at] = byte;
            bad.push(v);
        }
        let call = Call::SubmitCall {
            target: [0x51; 20],
            value: 5,
            gas: 6,
            data: vec![1, 2, 3],
        }
        .encode();
        bad.push(call[..4 + 128].to_vec());
        bad.push(call[..call.len() - 1].to_vec());
        for (at, byte) in [
            (4, 1),
            (4 + 32, 1),
            (4 + 64 + 23, 1),
            (4 + 127, 96),
            (4 + 159, 33),
            (call.len() - 1, 1),
        ] {
            let mut v = call.clone();
            v[at] = byte;
            bad.push(v);
        }
        let mut reject = Call::Reject { id: 1 }.encode();
        reject.push(0);
        bad.push(reject);
        for (i, data) in bad.iter().enumerate() {
            assert_eq!(Call::decode(data), None, "case {i}");
        }
    }

    #[test]
    fn only_governance_calls_pay_the_surcharge() {
        let vote = Call::Vote {
            id: 1,
            support: true,
        }
        .encode();
        assert_eq!(surcharge(Some(&GOVERNANCE_ADDRESS), &vote), GOVERNANCE_GAS);
        assert_eq!(surcharge(Some(&[0x45; 20]), &vote), 0);
        assert_eq!(surcharge(None, &vote), 0);
        // An upgrade action (`cancel(bytes32)`), and calldata that is nothing.
        let cancel = [&[0xc4, 0xd2, 0x52, 0xf5][..], &[7; 32]].concat();
        assert_eq!(surcharge(Some(&GOVERNANCE_ADDRESS), &cancel), 0);
        assert_eq!(surcharge(Some(&GOVERNANCE_ADDRESS), &vote[..67]), 0);
        assert_eq!(surcharge(Some(&GOVERNANCE_ADDRESS), &[]), 0);
        // A governed call carries its own gas.
        let call = Call::SubmitCall {
            target: [0x51; 20],
            value: 0,
            gas: 70_000,
            data: vec![],
        }
        .encode();
        assert_eq!(
            surcharge(Some(&GOVERNANCE_ADDRESS), &call),
            GOVERNANCE_GAS + 70_000
        );
    }

    #[test]
    fn delegators_take_their_stake_out_of_their_validators_votes() {
        let members = [
            Member {
                weight: 10,
                vote: Some(true),
            },
            Member {
                weight: 6,
                vote: None,
            },
            Member {
                weight: 4,
                vote: Some(false),
            },
        ];
        // Nobody else: validators carry their whole weight.
        let t = tally(&members, &[]);
        assert_eq!((t.yes, t.no, t.total), (10, 4, 20));
        assert_eq!(t.effective, vec![10, 6, 4]);
        // A delegator behind members 0 and 1 votes no, one behind member 2 yes.
        let delegators = [
            Delegator {
                support: false,
                behind: vec![(0, 3), (1, 2)],
            },
            Delegator {
                support: true,
                behind: vec![(2, 1)],
            },
            Delegator {
                support: true,
                behind: vec![],
            },
        ];
        let t = tally(&members, &delegators);
        assert_eq!((t.yes, t.no, t.total), (7 + 1, 5 + 3, 20));
        assert_eq!(t.effective, vec![7, 4, 3]);
        assert_eq!(t.delegators, vec![5, 1, 0]);
        assert!(t.yes + t.no <= t.total);
        // Sums saturate.
        let big = [
            Member {
                weight: u64::MAX,
                vote: Some(true),
            },
            Member {
                weight: u64::MAX,
                vote: Some(false),
            },
        ];
        let heavy = [Delegator {
            support: true,
            behind: vec![(0, u64::MAX), (1, 5)],
        }];
        let t = tally(&big, &heavy);
        assert_eq!((t.yes, t.no, t.total), (u64::MAX, u64::MAX - 5, u64::MAX));
        assert_eq!(t.effective, vec![0, u64::MAX - 5]);
        let lopsided = [
            Delegator {
                support: false,
                behind: vec![(0, u64::MAX)],
            },
            Delegator {
                support: false,
                behind: vec![(0, 1)],
            },
        ];
        let t = tally(&big, &lopsided);
        assert_eq!((t.yes, t.no), (0, u64::MAX));
        assert_eq!(Tally::default().effective, Vec::<u64>::new());
        assert!(!alloc::format!("{:?}", (members[0], &delegators[0], &t)).is_empty());
    }

    /// A chain's staking and one proposal's votes, as the kernel keeps them:
    /// stakes in gwei, and the running sums the kernel updates on every vote
    /// and every delegation change, but not on a slash, which jails for good.
    #[derive(Default)]
    struct World {
        /// Each validator's own stake, whether it is jailed, whether it is in
        /// the current set, and its vote.
        validators: Vec<(u128, bool, bool, Option<bool>)>,
        /// Each delegation's bonded stake, by validator and delegator.
        delegations: alloc::collections::BTreeMap<(usize, usize), u128>,
        /// The delegators' votes, in the order they first voted.
        ballots: Vec<(usize, bool)>,
        /// The running sums, by validator.
        moved: alloc::collections::BTreeMap<usize, Moved>,
    }

    fn capped(x: u128) -> u64 {
        u64::try_from(x).unwrap_or(u64::MAX)
    }

    impl World {
        fn support(&self, d: usize) -> Option<bool> {
            self.ballots.iter().find(|b| b.0 == d).map(|b| b.1)
        }

        /// A delegation's stake changes to `stake`: the staking hook.
        fn set_delegation(&mut self, v: usize, d: usize, stake: u128) {
            let old = self.delegations.insert((v, d), stake).unwrap_or(0);
            if let Some(support) = self.support(d) {
                let m = self.moved.entry(v).or_default();
                m.shift(support, capped(old), capped(stake));
            }
        }

        /// A delegator votes, or votes again.
        fn ballot(&mut self, d: usize, support: bool) {
            let before = self.support(d);
            if before == Some(support) {
                return;
            }
            match before {
                Some(_) => self.ballots.iter_mut().find(|b| b.0 == d).unwrap().1 = support,
                None => self.ballots.push((d, support)),
            }
            let mine: Vec<(usize, u128)> = self
                .delegations
                .iter()
                .filter(|((_, x), _)| *x == d)
                .map(|((v, _), s)| (*v, *s))
                .collect();
            for (v, stake) in mine {
                let m = self.moved.entry(v).or_default();
                if let Some(old) = before {
                    m.shift(old, capped(stake), 0);
                }
                m.shift(support, 0, capped(stake));
            }
        }

        /// The members that count, by validator index, with their weights.
        fn members(&self) -> Vec<(usize, Member)> {
            self.validators
                .iter()
                .enumerate()
                .filter(|(_, v)| v.2 && !v.1)
                .map(|(i, v)| {
                    let delegated: u128 = self
                        .delegations
                        .iter()
                        .filter(|((x, _), _)| *x == i)
                        .map(|(_, s)| *s)
                        .sum();
                    let weight = capped(v.0 + delegated);
                    (i, Member { weight, vote: v.3 })
                })
                .collect()
        }

        fn check(&self) -> Result<(), TestCaseError> {
            let members = self.members();
            let list: Vec<Member> = members.iter().map(|(_, m)| *m).collect();
            let delegators: Vec<Delegator> = self
                .ballots
                .iter()
                .map(|(d, support)| Delegator {
                    support: *support,
                    behind: members
                        .iter()
                        .enumerate()
                        .filter_map(|(at, (v, _))| {
                            let s = self.delegations.get(&(*v, *d))?;
                            Some((at, capped(*s)))
                        })
                        .collect(),
                })
                .collect();
            let t = tally(&list, &delegators);
            let running: Vec<(Member, Moved)> = members
                .iter()
                .map(|(v, m)| (*m, self.moved.get(v).cloned().unwrap_or_default()))
                .collect();
            prop_assert_eq!(running_tally(&running), (t.yes, t.no, t.total));
            Ok(())
        }
    }

    /// An amount of gwei: mostly small, sometimes near the top of `u64`,
    /// where the sums saturate.
    fn amount(seed: u64) -> u128 {
        if seed.is_multiple_of(8) {
            u128::from(u64::MAX - seed % 1_000)
        } else {
            u128::from(seed % 1_000)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The running tally the kernel keeps equals [`tally`] from scratch
        /// after every step of a random history of bonds, delegations,
        /// undelegations, slashes, set changes and votes.
        #[test]
        fn running_tallies_equal_the_tally_from_scratch(
            n in 1usize..6,
            steps in proptest::collection::vec((0u8..9, any::<u8>(), any::<u8>(), any::<u64>()), 1..80),
        ) {
            let mut w = World::default();
            for i in 0..n {
                w.validators.push((amount(i as u64 + 1), false, true, None));
            }
            for (kind, a, b, seed) in steps {
                let v = usize::from(a) % n;
                let d = usize::from(b) % 6;
                let stake = w.delegations.get(&(v, d)).copied().unwrap_or(0);
                match kind {
                    // Delegate, only behind a validator that is not jailed.
                    0 | 1 if !w.validators[v].1 => w.set_delegation(v, d, stake + amount(seed)),
                    // Undelegate part or all of it.
                    2 => w.set_delegation(v, d, stake - stake * u128::from(seed % 3) / 2),
                    3 | 4 => w.ballot(d, seed % 2 == 0),
                    5 => w.validators[v].3 = Some(seed % 2 == 0),
                    // A slash: the validator is jailed, its stake and every
                    // delegation behind it cut, with no hook.
                    6 => {
                        w.validators[v].1 = true;
                        w.validators[v].0 -= w.validators[v].0 / 10;
                        for ((x, _), s) in &mut w.delegations {
                            if *x == v {
                                *s -= *s / 10;
                            }
                        }
                    }
                    7 => w.validators[v].2 = !w.validators[v].2,
                    8 => w.validators[v].0 += amount(seed),
                    _ => {}
                }
                w.check()?;
            }
        }
    }

    #[test]
    fn running_sums_shift_between_sides() {
        let mut m = Moved::default();
        m.shift(true, 0, 5);
        m.shift(false, 0, 3);
        m.shift(true, 5, 2);
        assert_eq!((m.yes, m.no), (2, 3));
        // Stale sums behind a jailed validator only saturate.
        m.shift(false, 7, 0);
        assert_eq!((m.yes, m.no), (2, 0));
        let member = |weight, vote| Member { weight, vote };
        let r = running_tally(&[
            (member(10, Some(true)), Moved { yes: 0, no: 4 }),
            (member(6, None), Moved { yes: 1, no: 0 }),
            (member(3, Some(false)), Moved { yes: 9, no: 0 }),
        ]);
        assert_eq!(r, (6 + 1 + 9, 4, 19));
        let r = running_tally(&[(
            member(u64::MAX, Some(false)),
            Moved {
                yes: u128::MAX,
                no: 1,
            },
        )]);
        assert_eq!(r, (u64::MAX, 1, u64::MAX));
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
        let l = fee_params_log(&FeeParams {
            denominator: 5,
            elasticity: 6,
            min_base_fee: 7,
            treasury: [8; 20],
        });
        assert_eq!(
            l.data,
            [word(5), word(6), word(7), address_word(&[8; 20])].concat()
        );
        assert_eq!(l.topics.0, vec![event::FEE_PARAMS_SET]);
        let l = call_executed_log(3, &[4; 20], true, 21_000, &[5; 40]);
        assert_eq!(
            l.topics.0,
            vec![event::CALL_EXECUTED, word(3), address_word(&[4; 20])]
        );
        assert_eq!(l.data.len(), 32 * 4 + 64);
        assert_eq!(
            (l.data[31], l.data[62], l.data[95], l.data[127]),
            (1, 0x52, 96, 40)
        );
        let l = call_executed_log(0, &[4; 20], false, 0, &[5; MAX_CALL_OUTPUT + 1]);
        assert_eq!(l.data.len(), 32 * 4 + MAX_CALL_OUTPUT);
        assert_eq!(l.data[31], 0);
    }
}
