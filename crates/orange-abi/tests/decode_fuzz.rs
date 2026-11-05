//! Seeded fuzzing of every decoder in this crate: the canonical codec of
//! spec 06 for every record and hand-written type, and the Solidity
//! calldata of the outbox, staking, governance and module-install calls.
//! Random and mutated bytes never panic a decoder, and whatever a decoder
//! accepts is canonical: it re-encodes to exactly the bytes it came from.
//! See `orange-fuzz` for the long mode.

use std::fmt::Debug;

use orange_abi::codec::Seq;
use orange_abi::{Decode, Encode};
use orange_abi::{
    bridge, bridge_in, chain, conformance, fees, governance, modules, rotation, staking, types,
};
use orange_fuzz::{Rng, evolve, zero_seeds};

/// Cases per codec type.
const CASES: u64 = 400;

fn codec<T: Encode + Decode + PartialEq + Debug>(name: &str) {
    codec_with::<T>(name, |_, _| false);
}

/// [`codec`], where `legacy(input, encoding)` names the other encodings a
/// type accepts on purpose.
fn codec_with<T: Encode + Decode + PartialEq + Debug>(
    name: &str,
    legacy: fn(&[u8], &[u8]) -> bool,
) {
    evolve(name, CASES, zero_seeds(4, 160), |bytes| {
        let Ok(value) = T::from_bytes(bytes) else {
            return false;
        };
        let encoding = value.to_bytes();
        assert!(
            encoding == bytes || legacy(bytes, &encoding),
            "{name}: {value:?} is not canonical"
        );
        assert_eq!(T::from_bytes(&encoding).as_ref(), Ok(&value));
        true
    });
}

#[test]
fn a_proposal_also_reads_the_record_stored_before_governed_calls() {
    // The record of a kernel before governed calls ends after `total`; it
    // reads with no value and no gas (16 + 8 zero bytes when re-encoded).
    codec_with::<governance::Proposal>("codec-Proposal", |input, encoding| {
        encoding.len() == input.len() + 24
            && encoding.starts_with(input)
            && encoding[input.len()..].iter().all(|b| *b == 0)
    });
}

#[test]
fn a_dkg_run_also_reads_the_record_stored_before_shares_followed_stake() {
    // That record ends after `previous` and reads with one share per
    // recipient.
    codec_with::<staking::DkgRun>("codec-DkgRun", |input, encoding| {
        encoding.starts_with(input)
            && Seq::<u32>::from_bytes(&encoding[input.len()..])
                .is_ok_and(|s| s.0.iter().all(|n| *n == 1))
    });
}

macro_rules! codecs {
    ($($module:ident :: $ty:ident),* $(,)?) => {
        #[test]
        fn every_codec_type_decodes_only_canonical_bytes() {
            $(codec::<$module::$ty>(concat!("codec-", stringify!($ty)));)*
        }
    };
}

codecs!(
    bridge::FinalityProof,
    bridge_in::Fork,
    bridge_in::LightClientConfig,
    bridge_in::InboxLimits,
    bridge_in::BridgeInParams,
    chain::Account,
    chain::Allocation,
    chain::StorageSlot,
    chain::UpgradeParams,
    chain::BlockHeader,
    chain::Receipt,
    chain::Log,
    chain::StorageQuery,
    chain::AccessItem,
    chain::CallRequest,
    chain::SignedAuthorization,
    chain::CallResult,
    chain::DriverState,
    chain::SnapshotRecord,
    chain::Validator,
    chain::ValidatorSet,
    chain::Proposal,
    chain::SignedVote,
    chain::Certificate,
    chain::SignedHash,
    chain::Evidence,
    chain::Participation,
    chain::SimplexState,
    chain::SyncRequest,
    chain::SyncResponse,
    chain::GenesisParams,
    chain::Signature,
    chain::ConsensusMessage,
    conformance::Env,
    conformance::Case,
    conformance::Outcome,
    fees::FeeParams,
    fees::FeeStatus,
    governance::GovernanceParams,
    governance::OpenProposal,
    governance::Ballot,
    governance::BallotEntry,
    governance::Moved,
    governance::Sweep,
    governance::Execution,
    governance::DelegatorBallot,
    governance::ProposalView,
    governance::GovernanceStatus,
    modules::ModuleRecord,
    modules::Write,
    modules::CallContext,
    modules::ModuleQuery,
    modules::ModuleOutput,
    modules::ModuleCall,
    rotation::RotationShare,
    rotation::RotationCertificate,
    rotation::Handoff,
    rotation::ThresholdEvidence,
    staking::StakingParams,
    staking::ValidatorKey,
    staking::StakeRecord,
    staking::Delegation,
    staking::DelegationEntry,
    staking::StakeEntry,
    staking::KeySetRecord,
    staking::DkgProgress,
    staking::KeySetVote,
    staking::DkgEnvelope,
    staking::PartialShare,
    staking::StakingStatus,
    staking::DkgRequest,
    staking::KeystoreRequest,
    staking::DkgReply,
    types::ExecContext,
    types::Limits,
    types::Block,
    types::ExecuteSummary,
    types::ExecuteResult,
    types::ModuleInstall,
    types::Genesis,
    types::MigrateArgs,
    types::Ahead,
    types::ValidateArgs,
    types::BuildArgs,
    types::ExecuteArgs,
    types::FinalizeArgs,
    types::QueryArgs,
    types::QueryResult,
    types::ValidateResult,
    types::Input,
    types::Effect,
);

/// Calldata seeds: each selector followed by up to ten words, each zero or
/// a small number such as an offset or a length.
fn calldata_seeds(name: &str, selectors: &[[u8; 4]]) -> Vec<Vec<u8>> {
    let mut r = Rng::new(orange_fuzz::case_seed(name, 0, u64::MAX));
    let mut out = Vec::new();
    for sel in selectors {
        for _ in 0..120 {
            let mut data = sel.to_vec();
            for _ in 0..r.below(11) {
                let mut word = [0u8; 32];
                word[31] = *r.pick(&[0, 0, 1, 2, 20, 32, 48, 64, 96, 128, 160, 192]);
                data.extend_from_slice(&word);
            }
            if r.chance(1, 3) {
                data.extend_from_slice(&[0; 16]);
            }
            out.push(data);
        }
    }
    out
}

fn calldata<T: Debug>(
    name: &str,
    selectors: &[[u8; 4]],
    decode: fn(&[u8]) -> Option<T>,
    encode: fn(&T) -> Vec<u8>,
) {
    evolve(name, 3_000, calldata_seeds(name, selectors), |bytes| {
        let Some(call) = decode(bytes) else {
            return false;
        };
        assert_eq!(encode(&call), bytes, "{name}: {call:?} is not canonical");
        true
    });
}

#[test]
fn calldata_decoders_accept_only_canonical_calls() {
    calldata(
        "calldata-send",
        &[bridge::SEND_SELECTOR],
        bridge::SendCall::decode,
        bridge::SendCall::encode,
    );
    calldata(
        "calldata-install",
        &[modules::INSTALL_SELECTOR],
        modules::Install::decode,
        modules::Install::encode,
    );
    {
        use staking::selector as s;
        calldata(
            "calldata-staking",
            &[
                s::REGISTER,
                s::BOND,
                s::UNBOND,
                s::WITHDRAW,
                s::REPORT,
                s::DELEGATE,
                s::UNDELEGATE,
            ],
            staking::StakingAction::decode,
            staking::StakingAction::encode,
        );
    }
    {
        use governance::selector as s;
        calldata(
            "calldata-governance",
            &[
                s::SUBMIT,
                s::VOTE,
                s::EXECUTE,
                s::VETO,
                s::PAUSE,
                s::SET_GUARDIAN,
                s::SET_MODE,
                s::SET_PARAMS,
                s::SET_FEE_PARAMS,
                s::SUBMIT_CALL,
                s::REJECT,
            ],
            governance::Call::decode,
            governance::Call::encode,
        );
    }
}
