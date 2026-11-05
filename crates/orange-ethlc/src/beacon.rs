//! The light-client containers of the beacon chain at the Electra format,
//! which Fulu keeps (consensus-specs `electra/light-client/sync-protocol.md`,
//! `deneb/beacon-chain.md` for the execution payload header), their SSZ
//! decoding and their hash tree roots.
//!
//! The committee size is a parameter (512 on mainnet, 32 in the minimal
//! preset), so the same code reads both presets.

use alloc::vec::Vec;

use crate::ssz::{self, ZERO};
use crate::{Crypto, Hash};

/// Generalized index of the execution payload in a `BeaconBlockBody`.
pub const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
/// Generalized index of `finalized_checkpoint.root` in an Electra `BeaconState`.
pub const FINALIZED_ROOT_GINDEX: u64 = 169;
/// Generalized index of `current_sync_committee` in an Electra `BeaconState`.
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 86;
/// Generalized index of `next_sync_committee` in an Electra `BeaconState`.
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 87;

/// Hashes in an execution branch.
pub const EXECUTION_BRANCH: usize = 4;
/// Hashes in a finality branch.
pub const FINALITY_BRANCH: usize = 7;
/// Hashes in a sync-committee branch.
pub const COMMITTEE_BRANCH: usize = 6;

/// Bytes that are not the SSZ encoding the container requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// A cursor over SSZ bytes.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(n).ok_or(Malformed)?;
        let out = self.bytes.get(self.pos..end).ok_or(Malformed)?;
        self.pos = end;
        Ok(out)
    }

    fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn offset(&mut self) -> Result<usize, Malformed> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        Ok(self.take(N)?.try_into().expect("N bytes taken"))
    }

    fn hashes<const N: usize>(&mut self) -> Result<[Hash; N], Malformed> {
        let mut out = [ZERO; N];
        for h in &mut out {
            *h = self.array()?;
        }
        Ok(out)
    }
}

/// `N` bytes of `bytes` at `at`, which the caller has checked are there.
fn fixed<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[at..at + N]);
    out
}

/// A little-endian `u64` of `bytes` at `at`, which the caller has checked is there.
fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(fixed(bytes, at))
}

/// An SSZ offset: a 4-byte little-endian length.
fn offset(n: usize) -> [u8; 4] {
    u32::try_from(n)
        .expect("SSZ containers stay below 4 GiB")
        .to_le_bytes()
}

/// The variable-size parts of a container: `offsets` were read from its
/// fixed part, which ends at `fixed`; the first must point there, each at
/// or after the one before, and the last part runs to the end.
fn parts<'a>(bytes: &'a [u8], fixed: usize, offsets: &[usize]) -> Result<Vec<&'a [u8]>, Malformed> {
    if offsets.first() != Some(&fixed) {
        return Err(Malformed);
    }
    let mut out = Vec::new();
    for (i, start) in offsets.iter().enumerate() {
        let end = offsets.get(i + 1).copied().unwrap_or(bytes.len());
        out.push(bytes.get(*start..end).ok_or(Malformed)?);
    }
    Ok(out)
}

/// `BeaconBlockHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BeaconBlockHeader {
    /// Slot.
    pub slot: u64,
    /// Proposer index.
    pub proposer_index: u64,
    /// Parent block root.
    pub parent_root: Hash,
    /// State root.
    pub state_root: Hash,
    /// Body root.
    pub body_root: Hash,
}

impl BeaconBlockHeader {
    /// Encoded size.
    pub const SIZE: usize = 112;

    fn read(r: &mut Reader<'_>) -> Result<BeaconBlockHeader, Malformed> {
        let b = r.take(Self::SIZE)?;
        Ok(BeaconBlockHeader {
            slot: le64(b, 0),
            proposer_index: le64(b, 8),
            parent_root: fixed(b, 16),
            state_root: fixed(b, 48),
            body_root: fixed(b, 80),
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [
            &self.slot.to_le_bytes()[..],
            &self.proposer_index.to_le_bytes(),
            &self.parent_root,
            &self.state_root,
            &self.body_root,
        ]
        .concat()
    }

    /// `hash_tree_root`.
    #[must_use]
    pub fn root(&self, c: &dyn Crypto) -> Hash {
        let leaves = [
            ssz::uint64(self.slot),
            ssz::uint64(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
        ];
        ssz::merkleize(c, &leaves, 8)
    }
}

/// `ExecutionPayloadHeader` (Deneb, unchanged through Fulu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayloadHeader {
    /// Parent block hash.
    pub parent_hash: Hash,
    /// Fee recipient.
    pub fee_recipient: [u8; 20],
    /// The execution state root: what inbox proofs are checked against.
    pub state_root: Hash,
    /// Receipts root.
    pub receipts_root: Hash,
    /// Logs bloom, 256 bytes.
    pub logs_bloom: Vec<u8>,
    /// `prev_randao`.
    pub prev_randao: Hash,
    /// Block number.
    pub block_number: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas used.
    pub gas_used: u64,
    /// Timestamp.
    pub timestamp: u64,
    /// Extra data, at most 32 bytes.
    pub extra_data: Vec<u8>,
    /// Base fee per gas, a little-endian `uint256`.
    pub base_fee_per_gas: Hash,
    /// Block hash.
    pub block_hash: Hash,
    /// Transactions root.
    pub transactions_root: Hash,
    /// Withdrawals root.
    pub withdrawals_root: Hash,
    /// Blob gas used.
    pub blob_gas_used: u64,
    /// Excess blob gas.
    pub excess_blob_gas: u64,
}

impl Default for ExecutionPayloadHeader {
    fn default() -> Self {
        ExecutionPayloadHeader {
            parent_hash: ZERO,
            fee_recipient: [0; 20],
            state_root: ZERO,
            receipts_root: ZERO,
            logs_bloom: alloc::vec![0; 256],
            prev_randao: ZERO,
            block_number: 0,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            base_fee_per_gas: ZERO,
            block_hash: ZERO,
            transactions_root: ZERO,
            withdrawals_root: ZERO,
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }
}

impl ExecutionPayloadHeader {
    /// Size of the fixed part.
    pub const FIXED: usize = 584;

    /// Decodes the whole of `bytes`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<ExecutionPayloadHeader, Malformed> {
        if bytes.len() < Self::FIXED {
            return Err(Malformed);
        }
        let h = |at: usize| fixed::<32>(bytes, at);
        let extra_data = parts(
            bytes,
            Self::FIXED,
            &[u32::from_le_bytes(fixed(bytes, 436)) as usize],
        )?[0]
            .to_vec();
        if extra_data.len() > 32 {
            return Err(Malformed);
        }
        Ok(ExecutionPayloadHeader {
            parent_hash: h(0),
            fee_recipient: fixed(bytes, 32),
            state_root: h(52),
            receipts_root: h(84),
            logs_bloom: bytes[116..372].to_vec(),
            prev_randao: h(372),
            block_number: le64(bytes, 404),
            gas_limit: le64(bytes, 412),
            gas_used: le64(bytes, 420),
            timestamp: le64(bytes, 428),
            extra_data,
            base_fee_per_gas: h(440),
            block_hash: h(472),
            transactions_root: h(504),
            withdrawals_root: h(536),
            blob_gas_used: le64(bytes, 568),
            excess_blob_gas: le64(bytes, 576),
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::FIXED + self.extra_data.len());
        for part in [
            &self.parent_hash[..],
            &self.fee_recipient,
            &self.state_root,
            &self.receipts_root,
            &self.logs_bloom,
            &self.prev_randao,
        ] {
            out.extend_from_slice(part);
        }
        for v in [
            self.block_number,
            self.gas_limit,
            self.gas_used,
            self.timestamp,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&offset(Self::FIXED));
        for part in [
            &self.base_fee_per_gas,
            &self.block_hash,
            &self.transactions_root,
            &self.withdrawals_root,
        ] {
            out.extend_from_slice(part);
        }
        out.extend_from_slice(&self.blob_gas_used.to_le_bytes());
        out.extend_from_slice(&self.excess_blob_gas.to_le_bytes());
        out.extend_from_slice(&self.extra_data);
        out
    }

    /// `hash_tree_root`.
    #[must_use]
    pub fn root(&self, c: &dyn Crypto) -> Hash {
        let leaves = [
            self.parent_hash,
            ssz::chunks(&self.fee_recipient)[0],
            self.state_root,
            self.receipts_root,
            ssz::byte_vector(c, &self.logs_bloom),
            self.prev_randao,
            ssz::uint64(self.block_number),
            ssz::uint64(self.gas_limit),
            ssz::uint64(self.gas_used),
            ssz::uint64(self.timestamp),
            ssz::byte_list(c, &self.extra_data, 32),
            self.base_fee_per_gas,
            self.block_hash,
            self.transactions_root,
            self.withdrawals_root,
            ssz::uint64(self.blob_gas_used),
            ssz::uint64(self.excess_blob_gas),
        ];
        ssz::merkleize(c, &leaves, 32)
    }
}

/// `LightClientHeader` (Capella on): a beacon header and the execution
/// payload header its body commits to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LightClientHeader {
    /// The beacon block header.
    pub beacon: BeaconBlockHeader,
    /// The execution payload header.
    pub execution: ExecutionPayloadHeader,
    /// Its branch to `beacon.body_root`.
    pub execution_branch: [Hash; EXECUTION_BRANCH],
}

impl LightClientHeader {
    /// Size of the fixed part.
    pub const FIXED: usize = BeaconBlockHeader::SIZE + 4 + 32 * EXECUTION_BRANCH;

    /// Decodes the whole of `bytes`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<LightClientHeader, Malformed> {
        let mut r = Reader::new(bytes);
        let beacon = BeaconBlockHeader::read(&mut r)?;
        let execution = r.offset()?;
        let execution_branch = r.hashes()?;
        let execution =
            ExecutionPayloadHeader::decode(parts(bytes, Self::FIXED, &[execution])?[0])?;
        Ok(LightClientHeader {
            beacon,
            execution,
            execution_branch,
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.beacon.encode();
        out.extend_from_slice(&offset(Self::FIXED));
        for h in &self.execution_branch {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&self.execution.encode());
        out
    }

    /// `is_valid_light_client_header` from Capella on: the execution
    /// payload header is proven against the beacon block's body root.
    #[must_use]
    pub fn is_valid(&self, c: &dyn Crypto) -> bool {
        ssz::verify_branch(
            c,
            &self.execution.root(c),
            &self.execution_branch,
            EXECUTION_PAYLOAD_GINDEX,
            &self.beacon.body_root,
        )
    }
}

/// `SyncCommittee`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// The members' compressed G1 keys, 48 bytes each.
    pub pubkeys: Vec<u8>,
    /// Their aggregate.
    pub aggregate_pubkey: [u8; 48],
}

impl SyncCommittee {
    /// Encoded size for `size` members.
    #[must_use]
    pub fn encoded_size(size: usize) -> usize {
        48 * size + 48
    }

    fn read(r: &mut Reader<'_>, size: usize) -> Result<SyncCommittee, Malformed> {
        Ok(SyncCommittee {
            pubkeys: r.take(48 * size)?.to_vec(),
            aggregate_pubkey: r.array()?,
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [&self.pubkeys[..], &self.aggregate_pubkey].concat()
    }

    /// `hash_tree_root`.
    #[must_use]
    pub fn root(&self, c: &dyn Crypto) -> Hash {
        let keys: Vec<Hash> = self
            .pubkeys
            .chunks(48)
            .map(|k| ssz::byte_vector(c, k))
            .collect();
        let keys_root = ssz::merkleize(c, &keys, keys.len());
        ssz::pair(c, &keys_root, &ssz::byte_vector(c, &self.aggregate_pubkey))
    }
}

/// `SyncAggregate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// One bit per committee member, least significant bit first.
    pub bits: Vec<u8>,
    /// The aggregate signature, a compressed G2 point.
    pub signature: [u8; 96],
}

impl SyncAggregate {
    fn read(r: &mut Reader<'_>, size: usize) -> Result<SyncAggregate, Malformed> {
        Ok(SyncAggregate {
            bits: r.take(size / 8)?.to_vec(),
            signature: r.array()?,
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        [&self.bits[..], &self.signature].concat()
    }

    /// Whether member `i` signed.
    #[must_use]
    pub fn signed(&self, i: usize) -> bool {
        self.bits.get(i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)
    }

    /// How many members signed.
    #[must_use]
    pub fn participants(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// The keys of the members who signed, in committee order.
    #[must_use]
    pub fn participant_keys(&self, pubkeys: &[u8]) -> Vec<u8> {
        pubkeys
            .chunks(48)
            .enumerate()
            .filter(|(i, _)| self.signed(*i))
            .flat_map(|(_, k)| k.iter().copied())
            .collect()
    }
}

/// A light-client update: a `LightClientUpdate` or a
/// `LightClientFinalityUpdate`, which is one without a next sync committee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The header the sync committee signed.
    pub attested: LightClientHeader,
    /// The next sync committee in the attested state, and its branch;
    /// `None` for a finality update or a zero branch.
    pub next_sync_committee: Option<(SyncCommittee, [Hash; COMMITTEE_BRANCH])>,
    /// The finalized header the attested state names.
    pub finalized: LightClientHeader,
    /// Its branch to the attested state root; all zeros if there is none.
    pub finality_branch: [Hash; FINALITY_BRANCH],
    /// The committee's signature over the attested header.
    pub sync_aggregate: SyncAggregate,
    /// The slot whose committee signed.
    pub signature_slot: u64,
}

impl Update {
    /// Decodes an SSZ `LightClientUpdate` for committees of `size`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode_update(bytes: &[u8], size: usize) -> Result<Update, Malformed> {
        let mut r = Reader::new(bytes);
        let attested = r.offset()?;
        let committee = SyncCommittee::read(&mut r, size)?;
        let committee_branch: [Hash; COMMITTEE_BRANCH] = r.hashes()?;
        let finalized = r.offset()?;
        let finality_branch = r.hashes()?;
        let sync_aggregate = SyncAggregate::read(&mut r, size)?;
        let signature_slot = r.u64()?;
        let headers = parts(bytes, r.pos, &[attested, finalized])?;
        let next_sync_committee =
            (committee_branch != [ZERO; COMMITTEE_BRANCH]).then_some((committee, committee_branch));
        Ok(Update {
            attested: LightClientHeader::decode(headers[0])?,
            next_sync_committee,
            finalized: LightClientHeader::decode(headers[1])?,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }

    /// Decodes an SSZ `LightClientFinalityUpdate` for committees of `size`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode_finality_update(bytes: &[u8], size: usize) -> Result<Update, Malformed> {
        let mut r = Reader::new(bytes);
        let attested = r.offset()?;
        let finalized = r.offset()?;
        let finality_branch = r.hashes()?;
        let sync_aggregate = SyncAggregate::read(&mut r, size)?;
        let signature_slot = r.u64()?;
        let headers = parts(bytes, r.pos, &[attested, finalized])?;
        Ok(Update {
            attested: LightClientHeader::decode(headers[0])?,
            next_sync_committee: None,
            finalized: LightClientHeader::decode(headers[1])?,
            finality_branch,
            sync_aggregate,
            signature_slot,
        })
    }

    /// The SSZ `LightClientUpdate` encoding (a zero committee and branch if
    /// there is no next sync committee), for committees of `size`.
    #[must_use]
    pub fn encode_update(&self, size: usize) -> Vec<u8> {
        let attested = self.attested.encode();
        let finalized = self.finalized.encode();
        let (committee, branch) = match &self.next_sync_committee {
            Some((committee, branch)) => (committee.encode(), *branch),
            None => (
                alloc::vec![0; SyncCommittee::encoded_size(size)],
                [ZERO; COMMITTEE_BRANCH],
            ),
        };
        let fixed = 4
            + committee.len()
            + 32 * COMMITTEE_BRANCH
            + 4
            + 32 * FINALITY_BRANCH
            + self.sync_aggregate.bits.len()
            + 96
            + 8;
        let mut out = Vec::new();
        out.extend_from_slice(&offset(fixed));
        out.extend_from_slice(&committee);
        for h in &branch {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&offset(fixed + attested.len()));
        self.finality_branch
            .iter()
            .for_each(|h| out.extend_from_slice(h));
        out.extend_from_slice(&self.sync_aggregate.encode());
        out.extend_from_slice(&self.signature_slot.to_le_bytes());
        out.extend_from_slice(&attested);
        out.extend_from_slice(&finalized);
        out
    }

    /// The SSZ `LightClientFinalityUpdate` encoding.
    #[must_use]
    pub fn encode_finality_update(&self) -> Vec<u8> {
        let attested = self.attested.encode();
        let fixed = 8 + 32 * FINALITY_BRANCH + self.sync_aggregate.bits.len() + 96 + 8;
        let mut out = Vec::new();
        out.extend_from_slice(&offset(fixed));
        out.extend_from_slice(&offset(fixed + attested.len()));
        self.finality_branch
            .iter()
            .for_each(|h| out.extend_from_slice(h));
        out.extend_from_slice(&self.sync_aggregate.encode());
        out.extend_from_slice(&self.signature_slot.to_le_bytes());
        out.extend_from_slice(&attested);
        out.extend_from_slice(&self.finalized.encode());
        out
    }
}

/// `LightClientBootstrap`: a trusted header and the committee of its period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bootstrap {
    /// The header.
    pub header: LightClientHeader,
    /// The current sync committee in its state.
    pub current_sync_committee: SyncCommittee,
    /// The committee's branch to the header's state root.
    pub current_sync_committee_branch: [Hash; COMMITTEE_BRANCH],
}

impl Bootstrap {
    /// Decodes an SSZ `LightClientBootstrap` for committees of `size`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn decode(bytes: &[u8], size: usize) -> Result<Bootstrap, Malformed> {
        let mut r = Reader::new(bytes);
        let header = r.offset()?;
        let current_sync_committee = SyncCommittee::read(&mut r, size)?;
        let current_sync_committee_branch = r.hashes()?;
        let header = LightClientHeader::decode(parts(bytes, r.pos, &[header])?[0])?;
        Ok(Bootstrap {
            header,
            current_sync_committee,
            current_sync_committee_branch,
        })
    }

    /// The SSZ encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let committee = self.current_sync_committee.encode();
        let fixed = 4 + committee.len() + 32 * COMMITTEE_BRANCH;
        let mut out = offset(fixed).to_vec();
        out.extend_from_slice(&committee);
        self.current_sync_committee_branch
            .iter()
            .for_each(|h| out.extend_from_slice(h));
        out.extend_from_slice(&self.header.encode());
        out
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::testing::Native;

    fn header() -> LightClientHeader {
        let execution = ExecutionPayloadHeader {
            block_number: 7,
            extra_data: vec![1, 2, 3],
            ..ExecutionPayloadHeader::default()
        };
        LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: 9,
                ..BeaconBlockHeader::default()
            },
            execution,
            execution_branch: [[4; 32]; 4],
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn containers_round_trip_and_reject_bad_offsets() {
        let h = header();
        let bytes = h.encode();
        assert_eq!(
            bytes.len(),
            LightClientHeader::FIXED + ExecutionPayloadHeader::FIXED + 3
        );
        assert_eq!(LightClientHeader::decode(&bytes), Ok(h.clone()));
        // Truncated, an offset off by one, trailing extra data over 32 bytes.
        assert_eq!(LightClientHeader::decode(&bytes[..100]), Err(Malformed));
        let mut shifted = bytes.clone();
        shifted[112] += 1;
        assert_eq!(LightClientHeader::decode(&shifted), Err(Malformed));
        let mut long = h.clone();
        long.execution.extra_data = vec![0; 33];
        assert_eq!(LightClientHeader::decode(&long.encode()), Err(Malformed));
        let mut backwards = h.execution.encode();
        backwards[436..440].copy_from_slice(&700u32.to_le_bytes());
        assert_eq!(ExecutionPayloadHeader::decode(&backwards), Err(Malformed));
        assert_eq!(ExecutionPayloadHeader::decode(&[0; 10]), Err(Malformed));
        assert_eq!(Reader::new(&[]).take(usize::MAX), Err(Malformed));
        let mut r = Reader::new(&[0; 4]);
        r.pos = 1;
        assert_eq!(r.take(usize::MAX), Err(Malformed));

        let committee = SyncCommittee {
            pubkeys: vec![5; 48 * 4],
            aggregate_pubkey: [6; 48],
        };
        let aggregate = SyncAggregate {
            bits: vec![0b0000_0101],
            signature: [7; 96],
        };
        assert_eq!(
            (
                aggregate.participants(),
                aggregate.signed(2),
                aggregate.signed(1),
                aggregate.signed(99)
            ),
            (2, true, false, false)
        );
        let mut keys = vec![0u8; 48 * 8];
        keys[48 * 2] = 1;
        assert_eq!(
            aggregate.participant_keys(&keys),
            [vec![0; 48], {
                let mut k = vec![0; 48];
                k[0] = 1;
                k
            }]
            .concat()
        );
        let update = Update {
            attested: h.clone(),
            next_sync_committee: Some((committee.clone(), [[8; 32]; 6])),
            finalized: header(),
            finality_branch: [[9; 32]; 7],
            sync_aggregate: SyncAggregate {
                bits: vec![0b0000_0101],
                signature: [7; 96],
            },
            signature_slot: 10,
        };
        assert_eq!(
            Update::decode_update(&update.encode_update(4), 8),
            Err(Malformed)
        );
        let full = SyncCommittee {
            pubkeys: vec![5; 48 * 8],
            aggregate_pubkey: [6; 48],
        };
        let update = Update {
            next_sync_committee: Some((full, [[8; 32]; 6])),
            ..update
        };
        assert_eq!(
            Update::decode_update(&update.encode_update(8), 8),
            Ok(update.clone())
        );
        let finality = Update {
            next_sync_committee: None,
            ..update.clone()
        };
        assert_eq!(
            Update::decode_finality_update(&finality.encode_finality_update(), 8),
            Ok(finality.clone())
        );
        // A zero branch means no committee.
        assert_eq!(
            Update::decode_update(&finality.encode_update(8), 8),
            Ok(finality.clone())
        );
        let mut swapped = finality.encode_finality_update();
        swapped[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(Update::decode_finality_update(&swapped, 8), Err(Malformed));

        let bootstrap = Bootstrap {
            header: h,
            current_sync_committee: committee,
            current_sync_committee_branch: [[3; 32]; 6],
        };
        assert_eq!(
            Bootstrap::decode(&bootstrap.encode(), 4),
            Ok(bootstrap.clone())
        );
        assert_eq!(Bootstrap::decode(&bootstrap.encode(), 5), Err(Malformed));
    }

    #[test]
    fn roots_follow_the_ssz_rules() {
        let c = Native;
        let b = BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [3; 32],
            state_root: [4; 32],
            body_root: [5; 32],
        };
        let manual = ssz::merkleize(
            &c,
            &[
                ssz::uint64(1),
                ssz::uint64(2),
                [3; 32],
                [4; 32],
                [5; 32],
                ZERO,
                ZERO,
                ZERO,
            ],
            8,
        );
        assert_eq!(b.root(&c), manual);
        let committee = SyncCommittee {
            pubkeys: vec![1; 96],
            aggregate_pubkey: [2; 48],
        };
        let k = ssz::pair(&c, &[1; 32], &{
            let mut x = ZERO;
            x[..16].fill(1);
            x
        });
        let agg = ssz::pair(&c, &[2; 32], &{
            let mut x = ZERO;
            x[..16].fill(2);
            x
        });
        assert_eq!(
            committee.root(&c),
            ssz::pair(&c, &ssz::pair(&c, &k, &k), &agg)
        );
    }
}
