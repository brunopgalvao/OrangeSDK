//! What tests and relayer tooling need on a host (feature `testing`):
//! native crypto, hex, a synthetic beacon chain whose sync committees sign,
//! an Ethereum state with `eth_getProof`-style proofs, and an EVM to run the
//! bridge's contracts in.

use std::collections::BTreeMap;

use revm::context::result::{ExecutionResult, Output};
use revm::context::{Context, TxEnv};
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address as RAddress, Bytes, KECCAK_EMPTY, TxKind, U256};
use revm::{ExecuteCommitEvm, MainBuilder, MainContext};
use sha2::{Digest, Sha256};
use solo_abi::bridge_in::{Fork, LightClientConfig};
use solo_abi::codec::Seq;
use solo_abi::types::Address;
use solo_bls::curve::{G1Affine, G2Affine, G2Projective, Scalar};
use solo_rlp::{encode_bytes, encode_list, encode_uint};

use crate::beacon::{
    BeaconBlockHeader, Bootstrap, COMMITTEE_BRANCH, EXECUTION_BRANCH, ExecutionPayloadHeader,
    FINALITY_BRANCH, LightClientHeader, SyncAggregate, SyncCommittee, Update,
};
use crate::mpt::Trie;
use crate::ssz::{self, ZERO};
use crate::{Crypto, Hash, sync};

/// Field 22 of the beacon state, `current_sync_committee` (generalized index 86).
const CURRENT_SYNC_COMMITTEE_INDEX: usize = 22;
/// Field 23 of the beacon state, `next_sync_committee` (generalized index 87).
const NEXT_SYNC_COMMITTEE_INDEX: usize = 23;

/// Crypto on the host: `sha2`, `tiny-keccak` and `solo-bls`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Native;

impl Crypto for Native {
    fn sha256(&self, data: &[u8]) -> Hash {
        Sha256::digest(data).into()
    }

    fn keccak256(&self, data: &[u8]) -> Hash {
        keccak256(data)
    }

    fn fast_aggregate_verify(&self, keys: &[u8], msg: &Hash, signature: &[u8; 96]) -> bool {
        solo_bls::eth::fast_aggregate_verify(keys, msg, signature)
    }
}

/// Keccak-256.
#[must_use]
pub fn keccak256(data: &[u8]) -> Hash {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = ZERO;
    k.finalize(&mut out);
    out
}

/// Lower-case hex without a prefix.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Bytes from hex, with or without `0x`. A character that is not a hex
/// digit reads as zero, and an odd last digit as the high half of a byte.
#[must_use]
pub fn unhex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .trim()
        .trim_start_matches("0x")
        .chars()
        .map(|c| {
            c.to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .unwrap_or(0)
        })
        .collect();
    digits
        .chunks(2)
        .map(|p| p[0] << 4 | p.get(1).copied().unwrap_or(0))
        .collect()
}

/// A sync committee whose secret keys are known.
#[derive(Debug, Clone)]
pub struct Committee {
    secrets: Vec<Scalar>,
    /// The members' compressed keys, 48 bytes each.
    pub pubkeys: Vec<u8>,
}

impl Committee {
    /// `size` members derived from `seed`.
    #[must_use]
    pub fn new(seed: u64, size: usize) -> Committee {
        let secrets: Vec<Scalar> = (0..size as u64)
            .map(|i| Scalar::from(seed * 1_000_003 + i * 7_919 + 11))
            .collect();
        let pubkeys = secrets
            .iter()
            .flat_map(|s| G1Affine::from(G1Affine::generator() * s).to_compressed())
            .collect();
        Committee { secrets, pubkeys }
    }

    /// The committee as the beacon state holds it.
    #[must_use]
    pub fn sync_committee(&self) -> SyncCommittee {
        let sum: Scalar = self.secrets.iter().sum();
        SyncCommittee {
            pubkeys: self.pubkeys.clone(),
            aggregate_pubkey: G1Affine::from(G1Affine::generator() * sum).to_compressed(),
        }
    }

    /// The aggregate signature of the first `signers` members over `msg`,
    /// with their participation bits.
    #[must_use]
    pub fn sign(&self, signers: usize, msg: &Hash) -> SyncAggregate {
        let sum: Scalar = self.secrets[..signers].iter().sum();
        let h = G2Projective::from(solo_bls::hash::to_g2(msg, solo_bls::eth::DST));
        let mut bits = vec![0u8; self.secrets.len() / 8];
        for i in 0..signers {
            bits[i / 8] |= 1 << (i % 8);
        }
        SyncAggregate {
            bits,
            signature: G2Affine::from(h * sum).to_compressed(),
        }
    }
}

/// A beacon chain made up for tests: headers with an execution payload,
/// states that hold the finalized checkpoint and the sync committees, and
/// a committee per period that signs.
#[derive(Debug, Clone)]
pub struct Chain {
    /// Its configuration.
    pub config: LightClientConfig,
}

impl Chain {
    /// A chain in the minimal preset (8 slots an epoch, 8 epochs a period)
    /// with committees of `size`, forks at epochs 0 and 16.
    #[must_use]
    pub fn minimal(size: u32) -> Chain {
        Chain {
            config: LightClientConfig {
                genesis_validators_root: [0x42; 32],
                forks: Seq(vec![
                    Fork {
                        epoch: 0,
                        version: [5, 0, 0, 1],
                    },
                    Fork {
                        epoch: 16,
                        version: [6, 0, 0, 1],
                    },
                ]),
                sync_committee_size: size,
                slots_per_epoch: 8,
                epochs_per_period: 8,
            },
        }
    }

    fn size(&self) -> usize {
        self.config.sync_committee_size as usize
    }

    /// The committee of `period`.
    #[must_use]
    pub fn committee(&self, period: u64) -> Committee {
        Committee::new(period + 1, self.size())
    }

    /// A header at `slot` whose execution payload has `state_root` and
    /// block number `slot`, and whose state root is `state`.
    ///
    /// # Panics
    /// Never: a body of 16 fields has a branch of 4.
    #[must_use]
    pub fn header(&self, slot: u64, state_root: Hash, state: Hash) -> LightClientHeader {
        let c = Native;
        let execution = ExecutionPayloadHeader {
            state_root,
            block_number: slot,
            block_hash: c.keccak256(&slot.to_le_bytes()),
            extra_data: b"solo".to_vec(),
            ..ExecutionPayloadHeader::default()
        };
        let mut body: Vec<Hash> = (0..16u8).map(|i| [i; 32]).collect();
        body[9] = execution.root(&c);
        let branch: [Hash; EXECUTION_BRANCH] =
            ssz::branch(&c, &body, 9).try_into().expect("4 levels");
        let beacon = BeaconBlockHeader {
            slot,
            proposer_index: slot % 7,
            parent_root: [1; 32],
            state_root: state,
            body_root: ssz::merkleize(&c, &body, 16),
        };
        LightClientHeader {
            beacon,
            execution,
            execution_branch: branch,
        }
    }

    /// A beacon state's leaves: the finalized checkpoint (field 20) and the
    /// current and next committees (fields 22 and 23) of `period`.
    fn state_leaves(&self, period: u64, finalized: &BeaconBlockHeader) -> Vec<Hash> {
        let c = Native;
        let mut leaves: Vec<Hash> = (0..64u8).map(|i| [i; 32]).collect();
        let checkpoint_epoch = sync::epoch(&self.config, finalized.slot);
        leaves[20] = ssz::pair(&c, &ssz::uint64(checkpoint_epoch), &finalized.root(&c));
        leaves[22] = self.committee(period).sync_committee().root(&c);
        leaves[23] = self.committee(period + 1).sync_committee().root(&c);
        leaves
    }

    /// A checkpoint at `slot` with execution state root `state_root`.
    ///
    /// # Panics
    /// Never: a state of 64 fields has branches of 6.
    #[must_use]
    pub fn bootstrap(&self, slot: u64, state_root: Hash) -> Bootstrap {
        let c = Native;
        let period = sync::period(&self.config, slot);
        let leaves = self.state_leaves(period, &BeaconBlockHeader::default());
        let header = self.header(slot, state_root, ssz::merkleize(&c, &leaves, 64));
        let branch = ssz::branch(&c, &leaves, CURRENT_SYNC_COMMITTEE_INDEX)
            .try_into()
            .expect("6 levels");
        Bootstrap {
            header,
            current_sync_committee: self.committee(period).sync_committee(),
            current_sync_committee_branch: branch,
        }
    }

    /// An update attested at `attested`, finalizing `finalized`, carrying
    /// the next committee if `next`, signed in `signature_slot` by the first
    /// `signers` members of that slot's committee.
    ///
    /// # Panics
    /// If the signature slot is before the first fork.
    #[must_use]
    pub fn update(
        &self,
        attested: u64,
        finalized: &LightClientHeader,
        next: bool,
        signature_slot: u64,
        signers: usize,
    ) -> Update {
        let c = Native;
        let period = sync::period(&self.config, attested);
        let leaves = self.state_leaves(period, &finalized.beacon);
        let attested = self.header(attested, [0xA7; 32], ssz::merkleize(&c, &leaves, 64));
        let mut finality_branch = [ZERO; FINALITY_BRANCH];
        finality_branch[0] = ssz::uint64(sync::epoch(&self.config, finalized.beacon.slot));
        finality_branch[1..].copy_from_slice(&ssz::branch(&c, &leaves, 20));
        let next_sync_committee = next.then(|| {
            let branch: [Hash; COMMITTEE_BRANCH] =
                ssz::branch(&c, &leaves, NEXT_SYNC_COMMITTEE_INDEX)
                    .try_into()
                    .expect("6 levels");
            (self.committee(period + 1).sync_committee(), branch)
        });
        let root = sync::signing_root(&c, &self.config, &attested.beacon.root(&c), signature_slot)
            .expect("a known fork");
        let sync_aggregate = self
            .committee(sync::period(&self.config, signature_slot))
            .sign(signers, &root);
        Update {
            attested,
            next_sync_committee,
            finalized: finalized.clone(),
            finality_branch,
            sync_aggregate,
            signature_slot,
        }
    }
}

/// An Ethereum account.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    /// Nonce.
    pub nonce: u64,
    /// Balance.
    pub balance: u128,
    /// `keccak256` of its code.
    pub code_hash: Hash,
    /// Non-zero storage slots.
    pub storage: BTreeMap<Hash, Hash>,
}

/// An Ethereum state: its root and the proofs `eth_getProof` returns.
#[derive(Debug, Clone, Default)]
pub struct EthState {
    /// The accounts.
    pub accounts: BTreeMap<Address, Account>,
}

fn trimmed(value: &Hash) -> &[u8] {
    let zeros = value.iter().take_while(|b| **b == 0).count();
    &value[zeros..]
}

impl EthState {
    fn storage_trie(account: &Account) -> Trie {
        let mut t = Trie::new();
        for (slot, value) in &account.storage {
            let mut v = Vec::new();
            encode_bytes(trimmed(value), &mut v);
            t.insert(&keccak256(slot), &v);
        }
        t
    }

    fn state_trie(&self) -> Trie {
        let c = Native;
        let mut t = Trie::new();
        for (address, account) in &self.accounts {
            let mut payload = Vec::new();
            encode_uint(u128::from(account.nonce), &mut payload);
            encode_uint(account.balance, &mut payload);
            encode_bytes(&Self::storage_trie(account).root(&c), &mut payload);
            encode_bytes(&account.code_hash, &mut payload);
            let mut rlp = Vec::new();
            encode_list(&payload, &mut rlp);
            t.insert(&keccak256(address), &rlp);
        }
        t
    }

    /// The state root.
    #[must_use]
    pub fn root(&self) -> Hash {
        self.state_trie().root(&Native)
    }

    /// The account proof of `address` and the storage proof of `slot` in it.
    ///
    /// # Panics
    /// If the account does not exist.
    #[must_use]
    pub fn proof(&self, address: &Address, slot: &Hash) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let c = Native;
        let account = self.state_trie().prove(&c, &keccak256(address));
        let storage = Self::storage_trie(&self.accounts[address]).prove(&c, &keccak256(slot));
        (account, storage)
    }
}

/// An EVM at the Osaka fork over an in-memory state, for running the
/// bridge's contracts as Ethereum would.
#[derive(Debug, Default)]
pub struct Evm {
    db: CacheDB<EmptyDB>,
}

impl Evm {
    /// An empty state.
    #[must_use]
    pub fn new() -> Evm {
        Evm::default()
    }

    fn transact(&mut self, from: Address, kind: TxKind, data: Vec<u8>) -> ExecutionResult {
        let tx = TxEnv {
            caller: RAddress::from(from),
            gas_limit: 10_000_000,
            kind,
            data: Bytes::from(data),
            chain_id: Some(1),
            ..TxEnv::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.set_spec_and_mainnet_gas_params(SpecId::OSAKA);
                cfg.chain_id = 1;
                cfg.disable_nonce_check = true;
            })
            .with_db(&mut self.db)
            .build_mainnet();
        evm.transact_commit(tx).expect("a valid transaction")
    }

    /// Deploys `initcode` from `from`: the new contract's address, or
    /// `None` if the creation failed.
    pub fn deploy(&mut self, from: Address, initcode: Vec<u8>) -> Option<Address> {
        match self.transact(from, TxKind::Create, initcode) {
            ExecutionResult::Success {
                output: Output::Create(_, address),
                ..
            } => address.map(|a| a.0.0),
            _ => None,
        }
    }

    /// Calls `to` from `from`: the return data, or the revert data.
    ///
    /// # Errors
    /// The revert data, empty for a halt.
    pub fn call(&mut self, from: Address, to: Address, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        match self.transact(from, TxKind::Call(RAddress::from(to)), data) {
            ExecutionResult::Success { output, .. } => Ok(output.into_data().to_vec()),
            ExecutionResult::Revert { output, .. } => Err(output.to_vec()),
            ExecutionResult::Halt { .. } => Err(Vec::new()),
        }
    }

    /// The state the EVM holds, as Ethereum commits to it.
    #[must_use]
    pub fn state(&self) -> EthState {
        let mut out = EthState::default();
        for (address, a) in &self.db.cache.accounts {
            let storage = a
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (k.to_be_bytes::<32>(), v.to_be_bytes::<32>()))
                .collect();
            let code_hash = a.info.code_hash.0;
            let account = Account {
                nonce: a.info.nonce,
                balance: u128::try_from(a.info.balance).unwrap_or(u128::MAX),
                code_hash,
                storage,
            };
            if account.nonce != 0 || account.balance != 0 || code_hash != KECCAK_EMPTY.0 {
                out.accounts.insert(address.0.0, account);
            }
        }
        out
    }

    /// The value of `slot` of `address`.
    #[must_use]
    pub fn storage(&self, address: &Address, slot: &Hash) -> Hash {
        self.db
            .cache
            .accounts
            .get(&RAddress::from(*address))
            .and_then(|a| a.storage.get(&U256::from_be_bytes(*slot)))
            .map_or(ZERO, U256::to_be_bytes::<32>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_creation_has_no_address() {
        assert_eq!(Evm::new().deploy([1; 20], vec![0xFE]), None);
    }

    #[test]
    fn a_halting_call_has_no_data() {
        let mut evm = Evm::new();
        // Returns the one-byte runtime 0xFE, an invalid opcode.
        let to = evm
            .deploy(
                [1; 20],
                vec![0x60, 0xFE, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xF3],
            )
            .unwrap();
        assert_eq!(evm.call([1; 20], to, vec![]), Err(vec![]));
        // Runtimes that return one word, and that revert with nothing.
        let returns = evm
            .deploy(
                [1; 20],
                vec![
                    0x69, 0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3, 0x60, 0x00,
                    0x52, 0x60, 0x0a, 0x60, 0x16, 0xf3,
                ],
            )
            .unwrap();
        assert_eq!(evm.call([1; 20], returns, vec![]).unwrap()[31], 0x2a);
        let reverts = evm
            .deploy(
                [1; 20],
                vec![
                    0x64, 0x60, 0x00, 0x60, 0x00, 0xfd, 0x60, 0x00, 0x52, 0x60, 0x05, 0x60, 0x1b,
                    0xf3,
                ],
            )
            .unwrap();
        assert_eq!(evm.call([1; 20], reverts, vec![]), Err(vec![]));
        assert_eq!(evm.storage(&[9; 20], &ZERO), ZERO);
        assert_eq!(unhex("0x0aff"), vec![10, 255]);
        assert_eq!(unhex("zz1"), vec![0, 16]);
    }

    #[test]
    fn the_builders_print_and_copy() {
        let chain = Chain::minimal(8);
        let committee = chain.committee(0).clone();
        let account = Account::default();
        let state = EthState::default().clone();
        let text = format!(
            "{:?}{:?}{:?}{:?}{:?}{:?}",
            Native,
            chain.clone(),
            committee,
            account.clone(),
            state,
            Evm::new()
        );
        assert!(text.contains("Native") && text.contains("Chain") && text.contains("Evm"));
        assert_eq!(account, Account::default());
    }

    #[test]
    fn a_synthetic_chain_signs_what_the_protocol_accepts() {
        let c = Native;
        let chain = Chain::minimal(8);
        let mut evm = Evm::new();
        // Stores 0x2a at slot 0 and 0x0100 at slot 1, then stops.
        let code = vec![
            0x60, 0x2a, 0x60, 0x00, 0x55, 0x61, 0x01, 0x00, 0x60, 0x01, 0x55, 0x00,
        ];
        let to = evm.deploy([1; 20], code).unwrap();
        assert_eq!(evm.storage(&to, &ZERO)[31], 0x2a);
        let state = evm.state();
        let (account, storage) = state.proof(&to, &ZERO);
        let root = crate::inbox::storage_root(&c, &state.root(), &to, &account).unwrap();
        assert_eq!(
            crate::mpt::verify(&c, &root, &c.keccak256(&ZERO), &storage),
            Ok(Some(vec![0x2a]))
        );
        let message = crate::inbox::Message {
            nonce: 0,
            sender: [1; 20],
            recipient: [2; 20],
            gas_limit: 0,
            payload: vec![],
        };
        assert!(
            crate::inbox::verify(&c, &state.root(), &to, 1, &message, &account, &storage).is_err()
        );
        let b = chain.bootstrap(8, state.root());
        assert_eq!(sync::bootstrap(&c, &chain.config, &b), Ok(()));
        let f = chain.header(16, [1; 32], ZERO);
        let u = chain.update(20, &f, true, 21, 8);
        let st = sync::State {
            finalized_slot: 8,
            current: chain.committee(0).pubkeys,
            next: None,
        };
        let applied = sync::process(&c, &chain.config, &st, &u).unwrap();
        assert_eq!((applied.finalized, applied.committee), (true, Some(1)));
    }
}
